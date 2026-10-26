use super::iface::ScanTarget;
use crate::model::{DeviceUpdate, MacAddr};
use anyhow::Context;
use pnet::datalink::{self, Channel, Config};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub fn can_open(iface: &pnet::datalink::NetworkInterface) -> bool {
    let config = Config {
        read_timeout: Some(Duration::from_millis(50)),
        ..Config::default()
    };
    datalink::channel(iface, config).is_ok()
}

pub fn build_arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> [u8; 42] {
    let mut buf = [0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&src_mac.0);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&src_mac.0);
    buf[28..32].copy_from_slice(&src_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&dst_ip.octets());
    buf
}

pub fn parse_arp_reply(packet: &[u8]) -> Option<(MacAddr, Ipv4Addr)> {
    if packet.len() < 42 {
        return None;
    }
    if u16::from_be_bytes([packet[12], packet[13]]) != 0x0806 {
        return None;
    }
    if u16::from_be_bytes([packet[20], packet[21]]) != 2 {
        return None;
    }
    let mac = MacAddr([
        packet[22], packet[23], packet[24], packet[25], packet[26], packet[27],
    ]);
    if mac.is_dummy() {
        return None;
    }
    let ip = Ipv4Addr::new(packet[28], packet[29], packet[30], packet[31]);
    Some((mac, ip))
}

pub fn sweep_sync<F>(target: &ScanTarget, mut emit: F) -> anyhow::Result<Vec<Ipv4Addr>>
where
    F: FnMut(DeviceUpdate),
{
    let config = Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Config::default()
    };
    let channel = datalink::channel(&target.pnet_iface, config)
        .with_context(|| format!("opening datalink on {}", target.iface_name))?;
    let (mut tx, mut rx) = match channel {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("unsupported datalink channel"),
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stop);
    let our_mac = target
        .mac
        .or_else(|| target.pnet_iface.mac.map(|m| MacAddr(m.octets())));
    let Some(our_mac) = our_mac else {
        anyhow::bail!("no MAC address on {}", target.iface_name);
    };
    let our_ip = target.ipv4;
    let iface = target.iface_name.clone();
    let (found_tx, found_rx) = std::sync::mpsc::channel::<(MacAddr, Ipv4Addr)>();

    let reader = thread::spawn(move || {
        while !stop_reader.load(Ordering::Relaxed) {
            match rx.next() {
                Ok(packet) => {
                    if let Some((mac, ip)) = parse_arp_reply(packet) {
                        if mac != our_mac && ip != our_ip {
                            let _ = found_tx.send((mac, ip));
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    });

    let hosts = super::iface::scan_hosts(target.scan_network);
    for host in &hosts {
        let frame = build_arp_request(our_mac, target.ipv4, *host);
        let _ = tx.send_to(&frame, None);
        thread::sleep(Duration::from_millis(2));
    }
    thread::sleep(Duration::from_secs(2));
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();

    let mut found = Vec::new();
    while let Ok((mac, ip)) = found_rx.try_recv() {
        if !found.contains(&ip) {
            found.push(ip);
            emit(DeviceUpdate {
                ipv4: Some(ip),
                mac: Some(mac),
                interface: Some(iface.clone()),
                vendor: super::oui::vendor_for(mac),
                seen: true,
                ..DeviceUpdate::default()
            });
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_request_bytes() {
        let src_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let frame = build_arp_request(src_mac, src_ip, dst_ip);
        assert_eq!(
            &frame[..],
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06,
                0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0xc0, 0xa8, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            ]
        );
        assert_eq!(parse_arp_reply(&frame), None);
        let mut reply = frame;
        reply[20..22].copy_from_slice(&2u16.to_be_bytes());
        reply[22..28].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        reply[28..32].copy_from_slice(&dst_ip.octets());
        reply[6..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let (mac, ip) = parse_arp_reply(&reply).unwrap();
        assert_eq!(mac, MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));
        assert_eq!(ip, dst_ip);
    }
}
