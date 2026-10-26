use super::iface::ScanTarget;
use crate::model::{DeviceUpdate, MacAddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub iface: Option<String>,
}

pub fn collect(target: &ScanTarget) -> Vec<DeviceUpdate> {
    parse_neighbors()
        .into_iter()
        .filter(|entry| on_target(entry, target))
        .filter_map(|entry| neighbor_update(entry, &target.iface_name))
        .collect()
}

fn on_target(entry: &Neighbor, target: &ScanTarget) -> bool {
    if let Some(iface) = &entry.iface {
        if iface != &target.iface_name
            && iface.split('%').next() != Some(target.iface_name.as_str())
        {
            return false;
        }
    }
    match entry.ip {
        IpAddr::V4(ip) => {
            target.scan_network.contains(ip)
                || target.iface_network.contains(ip)
                || ip == target.ipv4
        }
        IpAddr::V6(_) => true,
    }
}

fn neighbor_update(entry: Neighbor, default_iface: &str) -> Option<DeviceUpdate> {
    let mac = entry.mac.filter(|m| !m.is_dummy())?;
    let vendor = super::oui::vendor_for(mac);
    match entry.ip {
        IpAddr::V4(ip) => Some(DeviceUpdate {
            ipv4: Some(ip),
            mac: Some(mac),
            vendor,
            interface: Some(entry.iface.unwrap_or_else(|| default_iface.to_string())),
            seen: true,
            ..DeviceUpdate::default()
        }),
        IpAddr::V6(ip) => Some(DeviceUpdate {
            ipv6: Some(ip),
            mac: Some(mac),
            vendor,
            interface: Some(entry.iface.unwrap_or_else(|| default_iface.to_string())),
            seen: true,
            ..DeviceUpdate::default()
        }),
    }
}

pub fn parse_neighbors() -> Vec<Neighbor> {
    if cfg!(target_os = "linux") {
        let mut entries = parse_proc_arp();
        entries.extend(parse_ip_neigh());
        dedup(entries)
    } else {
        let mut entries = parse_macos_arp();
        entries.extend(parse_macos_ndp());
        dedup(entries)
    }
}

fn dedup(mut entries: Vec<Neighbor>) -> Vec<Neighbor> {
    entries.sort_by_key(|a| a.ip);
    entries.dedup_by(|a, b| a.ip == b.ip && a.mac == b.mac);
    entries
}

fn parse_proc_arp() -> Vec<Neighbor> {
    let Ok(raw) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                return None;
            }
            let ip = Ipv4Addr::from_str(cols[0]).ok()?;
            let mac = MacAddr::from_str(cols[3]).ok();
            Some(Neighbor {
                ip: IpAddr::V4(ip),
                mac: mac.filter(|m| !m.is_zero()),
                iface: Some(cols[5].to_string()),
            })
        })
        .collect()
}

fn parse_ip_neigh() -> Vec<Neighbor> {
    let output = Command::new("ip").args(["neigh"]).output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_ip_neigh_line)
        .collect()
}

pub fn parse_ip_neigh_line(line: &str) -> Option<Neighbor> {
    let mut parts = line.split_whitespace();
    let ip = IpAddr::from_str(parts.next()?).ok()?;
    let mut iface = None;
    let mut mac = None;
    while let Some(token) = parts.next() {
        match token {
            "dev" => iface = parts.next().map(ToOwned::to_owned),
            "lladdr" => mac = parts.next().and_then(|v| MacAddr::from_str(v).ok()),
            _ => {}
        }
    }
    Some(Neighbor { ip, mac, iface })
}

fn parse_macos_arp() -> Vec<Neighbor> {
    let output = Command::new("/usr/sbin/arp").args(["-an"]).output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_macos_arp_line)
        .collect()
}

pub fn parse_macos_arp_line(line: &str) -> Option<Neighbor> {
    let ip_start = line.find('(')? + 1;
    let ip_end = line[ip_start..].find(')')? + ip_start;
    let ip = Ipv4Addr::from_str(&line[ip_start..ip_end]).ok()?;
    if line.contains("(incomplete)") {
        return Some(Neighbor {
            ip: IpAddr::V4(ip),
            mac: None,
            iface: iface_after(line, " on "),
        });
    }
    let at = line.find(" at ")?;
    let mac_start = at + 4;
    let mac_end = line[mac_start..]
        .find(char::is_whitespace)
        .map(|i| mac_start + i)
        .unwrap_or(line.len());
    let mac = MacAddr::from_str(line[mac_start..mac_end].trim()).ok();
    Some(Neighbor {
        ip: IpAddr::V4(ip),
        mac,
        iface: iface_after(line, " on "),
    })
}

fn parse_macos_ndp() -> Vec<Neighbor> {
    let output = Command::new("/usr/sbin/ndp").args(["-an"]).output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_macos_ndp_line)
        .collect()
}

pub fn parse_macos_ndp_line(line: &str) -> Option<Neighbor> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("Neighbor") {
        return None;
    }
    let mut parts = line.split_whitespace();
    let raw_ip = parts.next()?;
    let ip_text = raw_ip.split('%').next()?;
    let ip = Ipv6Addr::from_str(ip_text).ok()?;
    let mac_text = parts.next()?;
    if mac_text == "(incomplete)" {
        return Some(Neighbor {
            ip: IpAddr::V6(ip),
            mac: None,
            iface: parts.next().map(ToOwned::to_owned),
        });
    }
    let mac = MacAddr::from_str(mac_text).ok();
    Some(Neighbor {
        ip: IpAddr::V6(ip),
        mac,
        iface: parts.next().map(ToOwned::to_owned),
    })
}

fn iface_after(line: &str, marker: &str) -> Option<String> {
    let start = line.find(marker)? + marker.len();
    let rest = line[start..].trim();
    rest.split_whitespace().next().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_macos_arp_complete() {
        let line = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let n = parse_macos_arp_line(line).unwrap();
        assert_eq!(n.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(n.mac.unwrap().to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(n.iface.as_deref(), Some("en0"));
    }

    #[test]
    fn parse_macos_arp_short_mac() {
        let line = "? (192.168.1.1) at 20:37:f0:3e:7e:0 on en0 ifscope [ethernet]";
        let n = parse_macos_arp_line(line).unwrap();
        assert_eq!(n.mac.unwrap().to_string(), "20:37:f0:3e:7e:00");
    }

    #[test]
    fn parse_ndp_and_ip_neigh() {
        let ndp = parse_macos_ndp_line(
            "fe80::1%en0                      aa:bb:cc:dd:ee:ff  en0   permanent R",
        )
        .unwrap();
        assert_eq!(ndp.ip, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(ndp.iface.as_deref(), Some("en0"));
        let neigh = parse_ip_neigh_line("192.168.1.20 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE")
            .unwrap();
        assert_eq!(neigh.ip, "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!(neigh.mac.unwrap().to_string(), "11:22:33:44:55:66");
    }
}
