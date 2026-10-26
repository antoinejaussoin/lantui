use crate::model::DeviceUpdate;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub async fn reverse_many(ips: &[Ipv4Addr]) -> Vec<DeviceUpdate> {
    let servers = read_nameservers();
    if servers.is_empty() || ips.is_empty() {
        return Vec::new();
    }
    let Ok(resolver) = build_resolver(&servers) else {
        return Vec::new();
    };
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = Vec::new();
    for ip in ips.iter().copied() {
        let resolver = resolver.clone();
        let sem = std::sync::Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let lookup = resolver.reverse_lookup(IpAddr::V4(ip)).await.ok()?;
            let name = lookup.iter().next()?.to_utf8();
            let name = name.trim_end_matches('.');
            if name.is_empty() || name.ends_with(".local") {
                return None;
            }
            Some(DeviceUpdate {
                ipv4: Some(ip),
                dns_name: Some(name.to_string()),
                ..DeviceUpdate::default()
            })
        }));
    }
    let mut out = Vec::new();
    for task in tasks {
        if let Ok(Some(update)) = task.await {
            out.push(update);
        }
    }
    out
}

fn build_resolver(servers: &[IpAddr]) -> anyhow::Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::new();
    for ip in servers {
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(*ip, 53),
            Protocol::Udp,
        ));
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(*ip, 53),
            Protocol::Tcp,
        ));
    }
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(800);
    opts.attempts = 1;
    opts.use_hosts_file = false;
    Ok(TokioAsyncResolver::tokio(config, opts))
}

pub fn read_nameservers() -> Vec<IpAddr> {
    let Ok(raw) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nameserver")?;
            rest.trim().parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolv_conf_line() {
        let sample = "nameserver 1.1.1.1\n# nameserver 8.8.8.8\nnameserver 9.9.9.9\n";
        let mut found = Vec::new();
        for line in sample.lines() {
            if let Some(rest) = line.trim().strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    found.push(ip);
                }
            }
        }
        assert_eq!(found.len(), 2);
    }
}
