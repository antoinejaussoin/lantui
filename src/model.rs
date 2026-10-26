use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn oui24(self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }

    pub fn is_broadcast(self) -> bool {
        self.0 == [0xff; 6]
    }

    pub fn is_dummy(self) -> bool {
        self.is_zero() || self.is_broadcast() || self.0 == [0x02, 0, 0, 0, 0, 0]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split([':', '-', '.']).filter(|p| !p.is_empty()).collect();
        if parts.len() == 6 {
            let mut out = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                out[i] = u8::from_str_radix(part, 16)?;
            }
            return Ok(MacAddr(out));
        }
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 {
            anyhow::bail!("invalid MAC address: {s}");
        }
        let mut out = [0u8; 6];
        for i in 0..6 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
        }
        Ok(MacAddr(out))
    }
}

pub fn usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

pub fn usable_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeviceKey {
    Mac(MacAddr),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceKey::Mac(m) => write!(f, "{m}"),
            DeviceKey::Ipv4(ip) => write!(f, "{ip}"),
            DeviceKey::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnId {
    Status,
    Ipv4,
    Ipv6Ll,
    Ipv6Global,
    Mac,
    Hostname,
    Vendor,
    Ping,
    Mdns,
    Dns,
    Smb,
    SmbDomain,
    Services,
    Model,
    Interface,
    LastSeen,
    Comment,
}

impl ColumnId {
    pub const ALL: [ColumnId; 17] = [
        ColumnId::Status,
        ColumnId::Ipv4,
        ColumnId::Mac,
        ColumnId::Hostname,
        ColumnId::Vendor,
        ColumnId::Ping,
        ColumnId::Mdns,
        ColumnId::Ipv6Ll,
        ColumnId::Ipv6Global,
        ColumnId::Dns,
        ColumnId::Smb,
        ColumnId::SmbDomain,
        ColumnId::Services,
        ColumnId::Model,
        ColumnId::Interface,
        ColumnId::LastSeen,
        ColumnId::Comment,
    ];

    pub const DEFAULT_VISIBLE: [ColumnId; 7] = [
        ColumnId::Status,
        ColumnId::Ipv4,
        ColumnId::Mac,
        ColumnId::Hostname,
        ColumnId::Vendor,
        ColumnId::Ping,
        ColumnId::Mdns,
    ];

    pub fn title(self) -> &'static str {
        match self {
            ColumnId::Status => "ST",
            ColumnId::Ipv4 => "IPv4",
            ColumnId::Ipv6Ll => "IPv6 LL",
            ColumnId::Ipv6Global => "IPv6",
            ColumnId::Mac => "MAC",
            ColumnId::Hostname => "Hostname",
            ColumnId::Vendor => "Vendor",
            ColumnId::Ping => "Ping",
            ColumnId::Mdns => "mDNS",
            ColumnId::Dns => "DNS",
            ColumnId::Smb => "SMB",
            ColumnId::SmbDomain => "SMB domain",
            ColumnId::Services => "Services",
            ColumnId::Model => "Model",
            ColumnId::Interface => "Iface",
            ColumnId::LastSeen => "Seen",
            ColumnId::Comment => "Comment",
        }
    }

    pub fn width(self) -> u16 {
        match self {
            ColumnId::Status => 4,
            ColumnId::Ipv4 => 15,
            ColumnId::Ipv6Ll | ColumnId::Ipv6Global => 24,
            ColumnId::Mac => 17,
            ColumnId::Hostname | ColumnId::Mdns | ColumnId::Dns => 22,
            ColumnId::Vendor => 18,
            ColumnId::Ping => 8,
            ColumnId::Smb => 16,
            ColumnId::SmbDomain => 14,
            ColumnId::Services => 20,
            ColumnId::Model => 16,
            ColumnId::Interface => 8,
            ColumnId::LastSeen => 8,
            ColumnId::Comment => 16,
        }
    }

    pub fn is_pinned(self) -> bool {
        matches!(self, ColumnId::Status | ColumnId::Ipv4)
    }

    /// Higher values are hidden first when the terminal is too narrow.
    pub fn drop_priority(self) -> u8 {
        match self {
            ColumnId::Comment => 100,
            ColumnId::LastSeen => 95,
            ColumnId::Interface => 90,
            ColumnId::Model => 85,
            ColumnId::Services => 80,
            ColumnId::SmbDomain => 75,
            ColumnId::Ipv6Ll => 70,
            ColumnId::Ipv6Global => 65,
            ColumnId::Dns => 60,
            ColumnId::Smb => 55,
            ColumnId::Mdns => 50,
            ColumnId::Vendor => 40,
            ColumnId::Ping => 30,
            ColumnId::Mac => 20,
            ColumnId::Hostname => 10,
            ColumnId::Status => 5,
            ColumnId::Ipv4 => 0,
        }
    }
}

pub fn columns_fit_width(cols: &[ColumnId]) -> u16 {
    if cols.is_empty() {
        return 0;
    }
    cols.iter().map(|col| col.width()).sum::<u16>() + cols.len() as u16 - 1
}

/// Keep `cols` in their current order, dropping the lowest-value fields first
/// until they fit in `width` (including one space between columns).
pub fn fit_columns(mut cols: Vec<ColumnId>, width: u16) -> Vec<ColumnId> {
    if width == 0 {
        return Vec::new();
    }
    while cols.len() > 1 && columns_fit_width(&cols) > width {
        let drop_at = cols
            .iter()
            .enumerate()
            .max_by_key(|(_, col)| col.drop_priority())
            .map(|(idx, _)| idx)
            .expect("cols is non-empty");
        cols.remove(drop_at);
    }
    cols
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Device {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6_ll: Option<Ipv6Addr>,
    pub ipv6_global: Option<Ipv6Addr>,
    pub extra_ipv4: Vec<Ipv4Addr>,
    pub extra_ipv6: Vec<Ipv6Addr>,
    pub mac: Option<MacAddr>,
    pub vendor: String,
    pub ping_ms: Option<f64>,
    pub mdns_name: Option<String>,
    pub dns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub services: Vec<String>,
    pub model: Option<String>,
    pub interface: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub comment: Option<String>,
    pub online: bool,
    pub is_self: bool,
    pub new_this_sweep: bool,
    pub open_ports: Vec<u16>,
    #[serde(skip)]
    pub seen_generation: u64,
}

impl Device {
    pub fn hostname(&self) -> String {
        self.mdns_name
            .clone()
            .or_else(|| self.smb_name.clone())
            .or_else(|| self.dns_name.clone())
            .unwrap_or_default()
    }

    pub fn key(&self) -> Option<DeviceKey> {
        if let Some(mac) = self.mac {
            Some(DeviceKey::Mac(mac))
        } else if let Some(ip) = self.ipv4 {
            Some(DeviceKey::Ipv4(ip))
        } else {
            self.ipv6_ll.or(self.ipv6_global).map(DeviceKey::Ipv6)
        }
    }

    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.ipv4
            .map(IpAddr::V4)
            .or_else(|| self.ipv6_ll.map(IpAddr::V6))
            .or_else(|| self.ipv6_global.map(IpAddr::V6))
    }

    pub fn field(&self, col: ColumnId) -> String {
        match col {
            ColumnId::Status => {
                if self.is_self {
                    "me".into()
                } else if self.online {
                    "up".into()
                } else {
                    "down".into()
                }
            }
            ColumnId::Ipv4 => self.ipv4.map(|ip| ip.to_string()).unwrap_or_default(),
            ColumnId::Ipv6Ll => self.ipv6_ll.map(|ip| ip.to_string()).unwrap_or_default(),
            ColumnId::Ipv6Global => self
                .ipv6_global
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            ColumnId::Mac => self.mac.map(|m| m.to_string()).unwrap_or_default(),
            ColumnId::Hostname => self.hostname(),
            ColumnId::Vendor => self.vendor.clone(),
            ColumnId::Ping => self
                .ping_ms
                .map(|ms| format!("{ms:.1}ms"))
                .unwrap_or_default(),
            ColumnId::Mdns => self.mdns_name.clone().unwrap_or_default(),
            ColumnId::Dns => self.dns_name.clone().unwrap_or_default(),
            ColumnId::Smb => self.smb_name.clone().unwrap_or_default(),
            ColumnId::SmbDomain => self.smb_domain.clone().unwrap_or_default(),
            ColumnId::Services => self.services.join(", "),
            ColumnId::Model => self.model.clone().unwrap_or_default(),
            ColumnId::Interface => self.interface.clone().unwrap_or_default(),
            ColumnId::LastSeen => self
                .last_seen
                .map(|t| t.format("%H:%M:%S").to_string())
                .unwrap_or_default(),
            ColumnId::Comment => self.comment.clone().unwrap_or_default(),
        }
    }

    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        ColumnId::ALL
            .iter()
            .any(|col| self.field(*col).to_lowercase().contains(&q))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeviceUpdate {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mac: Option<MacAddr>,
    pub vendor: Option<String>,
    pub ping_ms: Option<f64>,
    pub ping_timeout: bool,
    pub mdns_name: Option<String>,
    pub dns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub service: Option<String>,
    pub model: Option<String>,
    pub interface: Option<String>,
    pub is_self: bool,
    pub comment: Option<String>,
    pub open_ports: Option<Vec<u16>>,
    pub seen: bool,
}

#[derive(Debug, Default)]
pub struct DeviceStore {
    by_key: HashMap<DeviceKey, Device>,
    generation: u64,
}

impl DeviceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn online_count(&self) -> usize {
        self.by_key.values().filter(|d| d.online).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.by_key.values()
    }

    pub fn get(&self, key: &DeviceKey) -> Option<&Device> {
        self.by_key.get(key)
    }

    pub fn get_mut(&mut self, key: &DeviceKey) -> Option<&mut Device> {
        self.by_key.get_mut(key)
    }

    pub fn begin_sweep(&mut self) {
        self.generation = self.generation.saturating_add(1);
        for device in self.by_key.values_mut() {
            device.new_this_sweep = false;
        }
    }

    pub fn finish_sweep(&mut self) {
        let gen = self.generation;
        for device in self.by_key.values_mut() {
            if device.seen_generation < gen && !device.is_self {
                device.online = false;
            }
        }
    }

    pub fn apply(&mut self, update: DeviceUpdate) -> Option<DeviceKey> {
        let key = self.resolve_key(&update)?;
        let existed = self.by_key.contains_key(&key);
        let gen = self.generation;
        let device = self.by_key.entry(key.clone()).or_default();
        let was_offline = existed && !device.online;
        let seen = update.seen || update.is_self;
        merge_update(device, update);
        if seen {
            device.seen_generation = gen;
        }
        if !existed || was_offline {
            device.new_this_sweep = true;
        }
        if let Some(name) = self.by_key.get(&key).and_then(|d| d.mdns_name.clone()) {
            self.merge_named_aliases(&key, &name);
        }
        Some(key)
    }

    fn resolve_key(&mut self, update: &DeviceUpdate) -> Option<DeviceKey> {
        if let Some(mac) = update.mac.filter(|m| !m.is_dummy()) {
            let mac_key = DeviceKey::Mac(mac);
            if let Some(ip) = update.ipv4 {
                if let Some(old) = self.by_key.remove(&DeviceKey::Ipv4(ip)) {
                    merge_device(self.by_key.entry(mac_key.clone()).or_default(), old);
                }
            }
            if let Some(ip6) = update.ipv6 {
                if let Some(old) = self.by_key.remove(&DeviceKey::Ipv6(ip6)) {
                    merge_device(self.by_key.entry(mac_key.clone()).or_default(), old);
                }
            }
            if let Some(name) = update.mdns_name.as_deref() {
                self.merge_named_aliases(&mac_key, name);
            }
            return Some(mac_key);
        }

        if let Some(ip) = update.ipv4.filter(|ip| usable_ipv4(*ip)) {
            if let Some(existing) = self.find_key_for_ipv4(ip) {
                return Some(existing);
            }
            if let Some(name) = update.mdns_name.as_deref() {
                if let Some(existing) = self.find_key_for_mdns(name) {
                    return Some(existing);
                }
            }
            return Some(DeviceKey::Ipv4(ip));
        }

        if let Some(ip6) = update.ipv6.filter(|ip| usable_ipv6(*ip)) {
            if let Some(existing) = self.find_key_for_ipv6(ip6) {
                return Some(existing);
            }
            if let Some(name) = update.mdns_name.as_deref() {
                if let Some(existing) = self.find_key_for_mdns(name) {
                    return Some(existing);
                }
            }
            if update.mdns_name.is_none() && update.dns_name.is_none() && update.smb_name.is_none()
            {
                return None;
            }
            return Some(DeviceKey::Ipv6(ip6));
        }

        if let Some(name) = update.mdns_name.as_deref() {
            if let Some(existing) = self.find_key_for_mdns(name) {
                return Some(existing);
            }
        }

        None
    }

    fn merge_named_aliases(&mut self, into: &DeviceKey, name: &str) {
        let aliases: Vec<DeviceKey> = self
            .by_key
            .iter()
            .filter(|(key, device)| *key != into && device.mdns_name.as_deref() == Some(name))
            .map(|(key, _)| key.clone())
            .collect();
        for alias in aliases {
            if let Some(old) = self.by_key.remove(&alias) {
                merge_device(self.by_key.entry(into.clone()).or_default(), old);
            }
        }
    }

    fn find_key_for_ipv4(&self, ip: Ipv4Addr) -> Option<DeviceKey> {
        self.by_key.iter().find_map(|(key, device)| {
            if device.ipv4 == Some(ip) || device.extra_ipv4.contains(&ip) {
                Some(key.clone())
            } else {
                None
            }
        })
    }

    fn find_key_for_mdns(&self, name: &str) -> Option<DeviceKey> {
        self.by_key.iter().find_map(|(key, device)| {
            if device.mdns_name.as_deref() == Some(name) {
                Some(key.clone())
            } else {
                None
            }
        })
    }

    fn find_key_for_ipv6(&self, ip: Ipv6Addr) -> Option<DeviceKey> {
        self.by_key.iter().find_map(|(key, device)| {
            if device.ipv6_ll == Some(ip)
                || device.ipv6_global == Some(ip)
                || device.extra_ipv6.contains(&ip)
            {
                Some(key.clone())
            } else {
                None
            }
        })
    }
}

fn merge_device(dst: &mut Device, src: Device) {
    let update = DeviceUpdate {
        ipv4: src.ipv4,
        ipv6: src.ipv6_ll.or(src.ipv6_global),
        mac: src.mac,
        vendor: nonempty_opt(&src.vendor),
        ping_ms: src.ping_ms,
        mdns_name: src.mdns_name,
        dns_name: src.dns_name,
        smb_name: src.smb_name,
        smb_domain: src.smb_domain,
        model: src.model,
        interface: src.interface,
        is_self: src.is_self,
        comment: src.comment,
        open_ports: if src.open_ports.is_empty() {
            None
        } else {
            Some(src.open_ports)
        },
        seen: src.online,
        ..DeviceUpdate::default()
    };
    merge_update(dst, update);
    for ip in src.extra_ipv4 {
        assign_ipv4(dst, ip);
    }
    for ip in src.extra_ipv6 {
        assign_ipv6(dst, ip);
    }
    for service in src.services {
        push_unique(&mut dst.services, service);
    }
    if src.seen_generation > dst.seen_generation {
        dst.seen_generation = src.seen_generation;
    }
}

fn merge_update(dst: &mut Device, update: DeviceUpdate) {
    if let Some(ip) = update.ipv4.filter(|ip| usable_ipv4(*ip)) {
        assign_ipv4(dst, ip);
    }
    if let Some(ip) = update.ipv6.filter(|ip| usable_ipv6(*ip)) {
        assign_ipv6(dst, ip);
    }
    if let Some(mac) = update.mac.filter(|m| !m.is_dummy()) {
        if dst.mac.is_none() || dst.mac.is_some_and(MacAddr::is_dummy) {
            dst.mac = Some(mac);
        }
    }
    if let Some(vendor) = update.vendor.filter(|v| !v.is_empty()) {
        if dst.vendor.is_empty() {
            dst.vendor = vendor;
        }
    }
    if update.ping_timeout {
        dst.ping_ms = None;
    } else if let Some(ms) = update.ping_ms {
        dst.ping_ms = Some(ms);
    }
    if let Some(name) = update.mdns_name.filter(|s| !s.is_empty()) {
        dst.mdns_name = Some(name);
    }
    if let Some(name) = update.dns_name.filter(|s| !s.is_empty()) {
        dst.dns_name = Some(name);
    }
    if let Some(name) = update.smb_name.filter(|s| !s.is_empty()) {
        dst.smb_name = Some(name);
    }
    if let Some(name) = update.smb_domain.filter(|s| !s.is_empty()) {
        dst.smb_domain = Some(name);
    }
    if let Some(service) = update.service.filter(|s| !s.is_empty()) {
        push_unique(&mut dst.services, service);
    }
    if let Some(model) = update.model.filter(|s| !s.is_empty()) {
        if dst.model.is_none() {
            dst.model = Some(model);
        }
    }
    if let Some(iface) = update.interface.filter(|s| !s.is_empty()) {
        if dst.interface.is_none() {
            dst.interface = Some(iface);
        }
    }
    if update.is_self {
        dst.is_self = true;
        dst.online = true;
    }
    if let Some(comment) = update.comment {
        dst.comment = if comment.is_empty() {
            None
        } else {
            Some(comment)
        };
    }
    if let Some(ports) = update.open_ports {
        dst.open_ports = ports;
    }
    if update.seen || update.is_self {
        dst.online = true;
        dst.last_seen = Some(Utc::now());
    }
}

fn assign_ipv4(dst: &mut Device, ip: Ipv4Addr) {
    if dst.ipv4.is_none() {
        dst.ipv4 = Some(ip);
    } else if dst.ipv4 != Some(ip) && !dst.extra_ipv4.contains(&ip) {
        dst.extra_ipv4.push(ip);
    }
}

fn assign_ipv6(dst: &mut Device, ip: Ipv6Addr) {
    if is_link_local(ip) {
        if dst.ipv6_ll.is_none() {
            dst.ipv6_ll = Some(ip);
        } else if dst.ipv6_ll != Some(ip) && !dst.extra_ipv6.contains(&ip) {
            dst.extra_ipv6.push(ip);
        }
    } else if dst.ipv6_global.is_none() {
        dst.ipv6_global = Some(ip);
    } else if dst.ipv6_global != Some(ip) && !dst.extra_ipv6.contains(&ip) {
        dst.extra_ipv6.push(ip);
    }
}

pub fn is_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn nonempty_opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&value))
    {
        list.push(value);
    }
}

pub fn cmp_devices(a: &Device, b: &Device, col: ColumnId, asc: bool) -> Ordering {
    let ord = match col {
        ColumnId::Ipv4 => cmp_opt(a.ipv4.map(u32::from), b.ipv4.map(u32::from)),
        ColumnId::Ping => match (a.ping_ms, b.ping_ms) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        ColumnId::Status => a
            .online
            .cmp(&b.online)
            .reverse()
            .then(a.is_self.cmp(&b.is_self).reverse()),
        ColumnId::LastSeen => cmp_opt(a.last_seen, b.last_seen),
        _ => a
            .field(col)
            .to_lowercase()
            .cmp(&b.field(col).to_lowercase()),
    };
    if asc {
        ord
    } else {
        ord.reverse()
    }
}

fn cmp_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_macos_short_octets() {
        assert_eq!(
            "20:37:f0:3e:7e:0".parse::<MacAddr>().unwrap().to_string(),
            "20:37:f0:3e:7e:00"
        );
        assert_eq!(
            "aa:46:cf:f7:75:d".parse::<MacAddr>().unwrap().to_string(),
            "aa:46:cf:f7:75:0d"
        );
    }

    #[test]
    fn merge_mdns_ipv6_into_named_ipv4() {
        let mut store = DeviceStore::new();
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 14)),
            mdns_name: Some("mbp".into()),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.apply(DeviceUpdate {
            ipv6: Some("fe80::1".parse().unwrap()),
            mdns_name: Some("mbp".into()),
            seen: true,
            ..DeviceUpdate::default()
        });
        assert_eq!(store.len(), 1);
        let device = store.iter().next().unwrap();
        assert_eq!(device.ipv4, Some(Ipv4Addr::new(192, 168, 1, 14)));
        assert_eq!(device.ipv6_ll, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn merge_by_mac_combines_ipv4_and_ipv6() {
        let mut store = DeviceStore::new();
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            mac: Some(mac("aa:bb:cc:dd:ee:ff")),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.apply(DeviceUpdate {
            ipv6: Some("fe80::1".parse().unwrap()),
            mac: Some(mac("aa:bb:cc:dd:ee:ff")),
            mdns_name: Some("printer".into()),
            seen: true,
            ..DeviceUpdate::default()
        });
        assert_eq!(store.len(), 1);
        let device = store.iter().next().unwrap();
        assert_eq!(device.ipv4, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(device.ipv6_ll, Some("fe80::1".parse().unwrap()));
        assert_eq!(device.mdns_name.as_deref(), Some("printer"));
    }

    #[test]
    fn ipv4_only_row_is_promoted_when_mac_arrives() {
        let mut store = DeviceStore::new();
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 5)),
            dns_name: Some("nas.lan".into()),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 5)),
            mac: Some(mac("11:22:33:44:55:66")),
            seen: true,
            ..DeviceUpdate::default()
        });
        assert_eq!(store.len(), 1);
        let device = store
            .get(&DeviceKey::Mac(mac("11:22:33:44:55:66")))
            .unwrap();
        assert_eq!(device.dns_name.as_deref(), Some("nas.lan"));
    }

    #[test]
    fn hostname_prefers_mdns_then_smb_then_dns() {
        let mut device = Device {
            dns_name: Some("host.lan".into()),
            smb_name: Some("HOST".into()),
            ..Device::default()
        };
        assert_eq!(device.hostname(), "HOST");
        device.mdns_name = Some("Host.local".into());
        assert_eq!(device.hostname(), "Host.local");
    }

    #[test]
    fn filter_matches_any_field() {
        let device = Device {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 40)),
            vendor: "Apple, Inc.".into(),
            mdns_name: Some("kitchen-homepod".into()),
            ..Device::default()
        };
        assert!(device.matches("homepod"));
        assert!(device.matches("192.168.1.40"));
        assert!(device.matches("apple"));
        assert!(!device.matches("windows"));
    }

    #[test]
    fn finish_sweep_marks_unseen_offline() {
        let mut store = DeviceStore::new();
        store.begin_sweep();
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 11)),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.begin_sweep();
        store.apply(DeviceUpdate {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            seen: true,
            ..DeviceUpdate::default()
        });
        store.finish_sweep();
        let online: Vec<_> = store
            .iter()
            .filter(|d| d.online)
            .filter_map(|d| d.ipv4)
            .collect();
        assert_eq!(online, vec![Ipv4Addr::new(192, 168, 1, 10)]);
    }

    #[test]
    fn sort_ipv4_and_ping() {
        let a = Device {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 20)),
            ping_ms: Some(12.0),
            ..Device::default()
        };
        let b = Device {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 2)),
            ping_ms: Some(3.0),
            ..Device::default()
        };
        assert_eq!(cmp_devices(&a, &b, ColumnId::Ipv4, true), Ordering::Greater);
        assert_eq!(cmp_devices(&a, &b, ColumnId::Ping, true), Ordering::Greater);
        assert_eq!(cmp_devices(&a, &b, ColumnId::Ping, false), Ordering::Less);
    }

    #[test]
    fn fit_columns_keeps_identity_when_narrow() {
        let wanted = vec![
            ColumnId::Status,
            ColumnId::Ipv4,
            ColumnId::Mac,
            ColumnId::Hostname,
            ColumnId::Vendor,
            ColumnId::Ping,
            ColumnId::Mdns,
            ColumnId::Comment,
        ];
        let wide = fit_columns(wanted.clone(), 200);
        assert_eq!(wide, wanted);

        let mid = fit_columns(wanted.clone(), 70);
        assert!(mid.contains(&ColumnId::Ipv4));
        assert!(mid.contains(&ColumnId::Hostname));
        assert!(!mid.contains(&ColumnId::Comment));
        assert!(!mid.contains(&ColumnId::Mdns));
        assert!(columns_fit_width(&mid) <= 70);

        let tight = fit_columns(wanted, 20);
        assert_eq!(tight, vec![ColumnId::Status, ColumnId::Ipv4]);
    }

    #[test]
    fn fit_columns_drops_ipv6_before_mac() {
        let fitted = fit_columns(
            vec![
                ColumnId::Ipv4,
                ColumnId::Mac,
                ColumnId::Ipv6Ll,
                ColumnId::Ipv6Global,
            ],
            40,
        );
        assert_eq!(fitted, vec![ColumnId::Ipv4, ColumnId::Mac]);
    }
}
