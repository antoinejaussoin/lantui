use crate::model::DeviceUpdate;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: ssdp:all\r\n\
\r\n";

pub async fn discover(wait: Duration) -> Vec<DeviceUpdate> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    let _ = sock
        .send_to(MSEARCH.as_bytes(), "239.255.255.250:1900")
        .await;
    let deadline = Instant::now() + wait;
    let mut updates = Vec::new();
    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        let mut buf = [0u8; 2048];
        match timeout(remain, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let std::net::IpAddr::V4(ip) = from.ip() {
                    if let Some(update) = parse_ssdp(&text, ip) {
                        updates.push(update);
                    }
                }
            }
            _ => break,
        }
    }
    updates
}

pub fn parse_ssdp(text: &str, ip: Ipv4Addr) -> Option<DeviceUpdate> {
    if !text.to_ascii_uppercase().contains("HTTP") {
        return None;
    }
    let st = header(text, "ST");
    let server = header(text, "SERVER");
    let service = st.or(server);
    Some(DeviceUpdate {
        ipv4: Some(ip),
        service,
        seen: true,
        ..DeviceUpdate::default()
    })
}

fn header(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(key) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssdp_response() {
        let text = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nSERVER: Linux/5.0 UPnP/1.0\r\n\r\n";
        let update = parse_ssdp(text, Ipv4Addr::new(192, 168, 1, 50)).unwrap();
        assert_eq!(update.ipv4, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(
            update.service.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaServer:1")
        );
    }
}
