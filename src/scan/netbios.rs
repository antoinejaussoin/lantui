use crate::model::DeviceUpdate;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const NBNS_PORT: u16 = 137;

pub fn build_node_status_query() -> Vec<u8> {
    let mut packet = vec![
        0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut name = [0u8; 16];
    name[0] = b'*';
    packet.push(0x20);
    for byte in name {
        packet.push(b'A' + (byte >> 4));
        packet.push(b'A' + (byte & 0x0f));
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
    packet
}

pub fn parse_node_status(buf: &[u8]) -> Option<(String, Option<String>)> {
    if buf.len() < 50 {
        return None;
    }
    let mut i = 12;
    i = skip_name(buf, i)?;
    if i + 10 > buf.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2 + 2 + 4;
    let rdlen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if rtype != 0x0021 || i >= buf.len() {
        return None;
    }
    let rdata = buf.get(i..i + rdlen.min(buf.len() - i))?;
    if rdata.is_empty() {
        return None;
    }
    let count = rdata[0] as usize;
    let mut smb_name = None;
    let mut domain = None;
    for idx in 0..count {
        let start = 1 + idx * 18;
        if start + 18 > rdata.len() {
            break;
        }
        let raw = &rdata[start..start + 15];
        let suffix = rdata[start + 15];
        let flags = u16::from_be_bytes([rdata[start + 16], rdata[start + 17]]);
        let name = String::from_utf8_lossy(raw).trim().to_string();
        if name.is_empty() || name.eq_ignore_ascii_case("__MSBROWSE__") {
            continue;
        }
        let group = flags & 0x8000 != 0;
        if !group && smb_name.is_none() && matches!(suffix, 0x00 | 0x20) {
            smb_name = Some(name);
        } else if group && domain.is_none() && suffix == 0x00 {
            domain = Some(name);
        }
    }
    smb_name.map(|name| (name, domain))
}

fn skip_name(buf: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= buf.len() {
            return None;
        }
        let len = buf[i];
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + len as usize;
    }
}

pub async fn query_many(ips: &[Ipv4Addr]) -> Vec<DeviceUpdate> {
    if ips.is_empty() {
        return Vec::new();
    }
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    let query = build_node_status_query();
    for ip in ips {
        let _ = sock.send_to(&query, (*ip, NBNS_PORT)).await;
    }
    let deadline = Instant::now() + Duration::from_millis(900);
    let mut updates = Vec::new();
    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        let mut buf = [0u8; 512];
        match timeout(remain, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Some((name, domain)) = parse_node_status(&buf[..n]) {
                    if let std::net::IpAddr::V4(ip) = from.ip() {
                        updates.push(DeviceUpdate {
                            ipv4: Some(ip),
                            smb_name: Some(name),
                            smb_domain: domain,
                            ..DeviceUpdate::default()
                        });
                    }
                }
            }
            _ => break,
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_nbstat_type() {
        let q = build_node_status_query();
        assert_eq!(&q[0..2], &[0x13, 0x37]);
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x21, 0x00, 0x01]);
        assert_eq!(q[12], 0x20);
    }

    #[test]
    fn parse_node_status_names() {
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&[0x00]);
        packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let mut rdata = vec![2u8];
        rdata.extend(nb_record(b"DESKTOP-ABC", 0x00, 0x0000));
        rdata.extend(nb_record(b"WORKGROUP", 0x00, 0x8000));
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        let (name, domain) = parse_node_status(&packet).unwrap();
        assert_eq!(name, "DESKTOP-ABC");
        assert_eq!(domain.as_deref(), Some("WORKGROUP"));
    }

    fn nb_record(name: &[u8], suffix: u8, flags: u16) -> Vec<u8> {
        let mut rec = vec![b' '; 15];
        rec[..name.len()].copy_from_slice(name);
        rec.push(suffix);
        rec.extend_from_slice(&flags.to_be_bytes());
        rec
    }
}
