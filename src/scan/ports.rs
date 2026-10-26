use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

pub const COMMON_PORTS: &[u16] = &[22, 80, 443, 445, 548, 631, 8080, 8443];

pub async fn probe(ip: IpAddr) -> Vec<u16> {
    let mut tasks = Vec::new();
    for &port in COMMON_PORTS {
        tasks.push(tokio::spawn(async move {
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(Duration::from_millis(350), TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        }));
    }
    let mut open = Vec::new();
    for task in tasks {
        if let Ok(Some(port)) = task.await {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}
