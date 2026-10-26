use crate::model::DeviceUpdate;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::net::IpAddr;
use std::time::Duration;

const SERVICE_TYPES: &[&str] = &[
    "_services._dns-sd._udp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_rdp._tcp.local.",
    "_adb._tcp.local.",
    "_androidtvremote2._tcp.local.",
    "_esphomelib._tcp.local.",
    "_sonos._tcp.local.",
    "_spotify-connect._tcp.local.",
];

pub fn spawn(tx: tokio::sync::mpsc::Sender<super::ScanEvent>) -> Option<ServiceDaemon> {
    let daemon = ServiceDaemon::new().ok()?;
    for service in SERVICE_TYPES {
        if let Ok(receiver) = daemon.browse(service) {
            let tx = tx.clone();
            let daemon_clone = daemon.clone();
            std::thread::spawn(move || drain(receiver, tx, daemon_clone));
        }
    }
    Some(daemon)
}

fn drain(
    receiver: mdns_sd::Receiver<ServiceEvent>,
    tx: tokio::sync::mpsc::Sender<super::ScanEvent>,
    daemon: ServiceDaemon,
) {
    while let Ok(event) = receiver.recv_timeout(Duration::from_secs(3600)) {
        match event {
            ServiceEvent::ServiceFound(ty, name) if ty.contains("_services._dns-sd._udp") => {
                if !name.is_empty() {
                    let _ = daemon.browse(&name);
                }
            }
            ServiceEvent::ServiceResolved(info) => {
                let hostname = clean_hostname(info.get_hostname());
                let instance = instance_name(info.get_fullname());
                let mdns_name = hostname.clone().or(instance);
                let model = txt_first(&info, &["model", "md", "am", "ty"]);
                let service = short_service(info.get_type());
                for addr in info.get_addresses() {
                    let mut update = DeviceUpdate {
                        mdns_name: mdns_name.clone(),
                        model: model.clone(),
                        service: service.clone(),
                        seen: true,
                        ..DeviceUpdate::default()
                    };
                    match addr {
                        IpAddr::V4(ip) if crate::model::usable_ipv4(*ip) => update.ipv4 = Some(*ip),
                        IpAddr::V6(ip) if crate::model::usable_ipv6(*ip) => update.ipv6 = Some(*ip),
                        _ => continue,
                    }
                    let _ = tx.blocking_send(super::ScanEvent::Device(update));
                }
            }
            ServiceEvent::SearchStarted(_)
            | ServiceEvent::SearchStopped(_)
            | ServiceEvent::ServiceRemoved(_, _)
            | ServiceEvent::ServiceFound(_, _) => {}
        }
    }
}

fn txt_first(info: &mdns_sd::ServiceInfo, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(prop) = info.get_property(key) {
            let value = prop.val_str().trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn clean_hostname(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_end_matches('.').trim_end_matches(".local");
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn instance_name(fullname: &str) -> Option<String> {
    let name = fullname.split("._").next()?.trim().trim_end_matches('.');
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn short_service(ty: &str) -> Option<String> {
    let short = ty
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .trim_start_matches('_');
    if short.is_empty() {
        None
    } else {
        Some(short.to_string())
    }
}
