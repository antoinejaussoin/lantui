use crate::model::Device;
use serde::Serialize;
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct DeviceExport {
    pub status: String,
    pub ipv4: Option<String>,
    pub ipv6_link_local: Option<String>,
    pub ipv6_global: Option<String>,
    pub mac: Option<String>,
    pub hostname: String,
    pub vendor: String,
    pub ping_ms: Option<f64>,
    pub mdns_name: Option<String>,
    pub dns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub services: String,
    pub model: Option<String>,
    pub interface: Option<String>,
    pub last_seen: Option<String>,
    pub comment: Option<String>,
    pub open_ports: String,
    pub is_self: bool,
}

impl From<&Device> for DeviceExport {
    fn from(device: &Device) -> Self {
        Self {
            status: device.field(crate::model::ColumnId::Status),
            ipv4: device.ipv4.map(|ip| ip.to_string()),
            ipv6_link_local: device.ipv6_ll.map(|ip| ip.to_string()),
            ipv6_global: device.ipv6_global.map(|ip| ip.to_string()),
            mac: device.mac.map(|mac| mac.to_string()),
            hostname: device.hostname(),
            vendor: device.vendor.clone(),
            ping_ms: device.ping_ms,
            mdns_name: device.mdns_name.clone(),
            dns_name: device.dns_name.clone(),
            smb_name: device.smb_name.clone(),
            smb_domain: device.smb_domain.clone(),
            services: device.services.join(", "),
            model: device.model.clone(),
            interface: device.interface.clone(),
            last_seen: device
                .last_seen
                .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            comment: device.comment.clone(),
            open_ports: device
                .open_ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            is_self: device.is_self,
        }
    }
}

pub fn write_json(devices: &[&Device], writer: impl Write) -> anyhow::Result<()> {
    let rows: Vec<DeviceExport> = devices.iter().copied().map(DeviceExport::from).collect();
    serde_json::to_writer_pretty(writer, &rows)?;
    Ok(())
}

pub fn write_csv(devices: &[&Device], writer: impl Write) -> anyhow::Result<()> {
    let mut csv = csv::Writer::from_writer(writer);
    for device in devices {
        csv.serialize(DeviceExport::from(*device))?;
    }
    csv.flush()?;
    Ok(())
}
