use crate::model::MacAddr;
use anyhow::{bail, Context};
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub iface_name: String,
    pub mac: Option<MacAddr>,
    pub ipv4: Ipv4Addr,
    pub prefix: u8,
    pub iface_network: Ipv4Network,
    pub scan_network: Ipv4Network,
    pub ipv6s: Vec<Ipv6Addr>,
    pub pnet_iface: NetworkInterface,
}

#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub prefix: Option<u8>,
    pub mac: Option<MacAddr>,
    pub up: bool,
    pub loopback: bool,
    pub point_to_point: bool,
}

pub fn list_ifaces() -> Vec<IfaceInfo> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| {
            let (ipv4, prefix) = first_ipv4(&iface);
            IfaceInfo {
                name: iface.name.clone(),
                ipv4,
                prefix,
                mac: iface
                    .mac
                    .map(|m| MacAddr(m.octets()))
                    .filter(|m| !m.is_dummy()),
                up: iface.is_up(),
                loopback: iface.is_loopback(),
                point_to_point: iface.is_point_to_point(),
            }
        })
        .collect()
}

pub fn resolve(iface: Option<&str>, range: Option<Ipv4Network>) -> anyhow::Result<ScanTarget> {
    let interfaces = datalink::interfaces();
    let chosen = if let Some(name) = iface {
        interfaces
            .into_iter()
            .find(|item| item.name == name)
            .with_context(|| format!("interface {name} not found"))?
    } else {
        pick_default(&interfaces).context("no suitable interface with IPv4 found")?
    };

    if chosen.is_loopback() && iface.is_none() {
        bail!("refusing to auto-select loopback {}", chosen.name);
    }

    let (ipv4, prefix) = match first_ipv4(&chosen) {
        (Some(ip), Some(prefix)) => (ip, prefix),
        _ => anyhow::bail!("interface {} has no IPv4 address", chosen.name),
    };
    let iface_network = Ipv4Network::new(ipv4, prefix)
        .with_context(|| format!("invalid prefix /{prefix} on {}", chosen.name))?;
    if prefix >= 31 {
        bail!(
            "interface {} is /{prefix}; /31 and /32 networks are skipped",
            chosen.name
        );
    }

    let scan_network = if let Some(range) = range {
        if range.prefix() < 16 {
            bail!("range {range} is too large; use /16 or longer");
        }
        range
    } else if prefix < 22 {
        let scan = Ipv4Network::new(ipv4, 24).context("could not build /24 scan range")?;
        Ipv4Network::new(scan.network(), 24).unwrap_or(scan)
    } else {
        iface_network
    };

    let mac = macos_iface_mac(&chosen.name)
        .or_else(|| chosen.mac.map(|m| MacAddr(m.octets())))
        .filter(|m| !m.is_dummy());

    let ipv6s = chosen
        .ips
        .iter()
        .filter_map(|ip| match ip.ip() {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    Ok(ScanTarget {
        iface_name: chosen.name.clone(),
        mac,
        ipv4,
        prefix,
        iface_network,
        scan_network,
        ipv6s,
        pnet_iface: chosen,
    })
}

fn pick_default(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {
    let default_name = default_iface_name();
    if let Some(name) = default_name {
        if let Some(iface) = interfaces.iter().find(|iface| {
            iface.name == name
                && !iface.is_loopback()
                && !iface.is_point_to_point()
                && first_ipv4(iface).0.is_some()
        }) {
            return Some(iface.clone());
        }
    }

    interfaces
        .iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && !iface.is_point_to_point()
                && first_ipv4(iface).0.is_some()
        })
        .cloned()
}

fn first_ipv4(iface: &NetworkInterface) -> (Option<Ipv4Addr>, Option<u8>) {
    iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            ipnetwork::IpNetwork::V4(v4) => Some((Some(v4.ip()), Some(v4.prefix()))),
            ipnetwork::IpNetwork::V6(_) => None,
        })
        .unwrap_or((None, None))
}

pub fn default_iface_name() -> Option<String> {
    if cfg!(target_os = "linux") {
        linux_default_iface()
    } else {
        macos_default_iface()
    }
}

fn linux_default_iface() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in raw.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

fn macos_iface_mac(name: &str) -> Option<MacAddr> {
    let output = Command::new("/sbin/ifconfig").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("ether ")
                .or_else(|| line.strip_prefix("lladdr "))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|mac| MacAddr::from_str(mac).ok())
        })
}

fn macos_default_iface() -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("interface:") {
            return Some(name.trim().to_string());
        }
    }
    None
}

pub fn scan_hosts(network: Ipv4Network) -> Vec<Ipv4Addr> {
    network
        .iter()
        .filter(|ip| *ip != network.network() && *ip != network.broadcast())
        .collect()
}
