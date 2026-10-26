use crate::model::DeviceUpdate;
use ipnetwork::Ipv4Network;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

const PING_TIMEOUT: Duration = Duration::from_millis(800);
const CONCURRENCY: usize = 32;

pub async fn sweep_subnet(network: Ipv4Network) -> Vec<(Ipv4Addr, Option<f64>)> {
    ping_hosts(&super::iface::scan_hosts(network)).await
}

pub async fn ping_hosts(hosts: &[Ipv4Addr]) -> Vec<(Ipv4Addr, Option<f64>)> {
    ping_hosts_from(hosts, None).await
}

pub async fn ping_hosts_from(
    hosts: &[Ipv4Addr],
    source: Option<Ipv4Addr>,
) -> Vec<(Ipv4Addr, Option<f64>)> {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::with_capacity(hosts.len());
    for host in hosts.iter().copied() {
        let sem = std::sync::Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let rtt = ping_one_from(host, source).await;
            Some((host, rtt))
        }));
    }
    let mut out = Vec::new();
    for task in tasks {
        if let Ok(Some(item)) = task.await {
            out.push(item);
        }
    }
    out
}

pub async fn ping_one(ip: Ipv4Addr) -> Option<f64> {
    ping_one_from(ip, None).await
}

pub async fn ping_one_from(ip: Ipv4Addr, source: Option<Ipv4Addr>) -> Option<f64> {
    if let Some(rtt) = icmp_ping(ip).await {
        return Some(rtt);
    }
    system_ping(ip, source).await
}

pub fn updates_from_results(
    results: &[(Ipv4Addr, Option<f64>)],
    iface: &str,
    only_alive: bool,
) -> Vec<DeviceUpdate> {
    results
        .iter()
        .filter(|(_, rtt)| !only_alive || rtt.is_some())
        .map(|(ip, rtt)| DeviceUpdate {
            ipv4: Some(*ip),
            ping_ms: *rtt,
            ping_timeout: rtt.is_none(),
            interface: Some(iface.to_string()),
            seen: rtt.is_some(),
            ..DeviceUpdate::default()
        })
        .collect()
}

async fn icmp_ping(ip: Ipv4Addr) -> Option<f64> {
    tokio::task::spawn_blocking(move || icmp_ping_sync(ip))
        .await
        .ok()?
}

fn icmp_ping_sync(ip: Ipv4Addr) -> Option<f64> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))
        .ok()?;
    socket.set_read_timeout(Some(PING_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(PING_TIMEOUT)).ok()?;
    let id = (std::process::id() as u16).wrapping_add(u32::from(ip) as u16);
    let seq = 1u16;
    let packet = echo_request(id, seq, b"lantui!");
    let dest = SockAddr::from(SocketAddrV4::new(ip, 0));
    let start = Instant::now();
    socket.send_to(&packet, &dest).ok()?;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                let reply = unsafe { assume_init_slice(&buf[..n]) };
                if is_echo_reply(reply, id, seq) {
                    return Some(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
            {
                return None;
            }
            Err(_) => return None,
        }
        if start.elapsed() > PING_TIMEOUT {
            return None;
        }
    }
}

unsafe fn assume_init_slice(buf: &[MaybeUninit<u8>]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), buf.len()) }
}

fn echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![8, 0, 0, 0];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);
    let sum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(odd) = remainder.first() {
        sum += (*odd as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn is_echo_reply(buf: &[u8], id: u16, seq: u16) -> bool {
    let icmp = if buf.len() > 20 && buf[0] >> 4 == 4 {
        &buf[20..]
    } else {
        buf
    };
    if icmp.len() < 8 || icmp[0] != 0 {
        return false;
    }
    u16::from_be_bytes([icmp[4], icmp[5]]) == id && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

async fn system_ping(ip: Ipv4Addr, source: Option<Ipv4Addr>) -> Option<f64> {
    tokio::task::spawn_blocking(move || system_ping_sync(ip, source))
        .await
        .ok()?
}

fn system_ping_sync(ip: Ipv4Addr, source: Option<Ipv4Addr>) -> Option<f64> {
    let (bin, mut args) = if cfg!(target_os = "macos") {
        (
            "/sbin/ping",
            vec!["-c".into(), "1".into(), "-W".into(), "800".into()],
        )
    } else {
        (
            "ping",
            vec!["-c".into(), "1".into(), "-W".into(), "1".into()],
        )
    };
    if let Some(src) = source {
        if cfg!(target_os = "macos") {
            args.extend(["-S".into(), src.to_string()]);
        } else {
            args.extend(["-I".into(), src.to_string()]);
        }
    }
    args.push(ip.to_string());
    let output = std::process::Command::new(bin).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ping_rtt(&String::from_utf8_lossy(&output.stdout))
}

fn parse_ping_rtt(text: &str) -> Option<f64> {
    for token in text.split_whitespace() {
        if let Some(rest) = token.strip_prefix("time=") {
            let rest = rest.trim_end_matches("ms");
            return rest.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_echo_request() {
        let packet = echo_request(0x1234, 0x0001, b"hi");
        assert_eq!(packet[0], 8);
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn parse_macos_and_linux_ping() {
        assert_eq!(
            parse_ping_rtt("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms"),
            Some(12.345)
        );
        assert_eq!(
            parse_ping_rtt("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=3.0 ms"),
            Some(3.0)
        );
    }
}
