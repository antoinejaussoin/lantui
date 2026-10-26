pub mod arp;
pub mod dns;
pub mod iface;
pub mod mdns;
pub mod neighbors;
pub mod netbios;
pub mod oui;
pub mod ping;
pub mod ports;
pub mod ssdp;

use crate::model::{DeviceUpdate, MacAddr};
use anyhow::Context;
use iface::ScanTarget;
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub iface: Option<String>,
    pub range: Option<Ipv4Network>,
    pub live: bool,
    pub interval: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            iface: None,
            range: None,
            live: false,
            interval: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ScanEvent {
    Started {
        iface: String,
        prefix: String,
        local_ipv4: Ipv4Addr,
        local_mac: Option<MacAddr>,
        active: bool,
    },
    Privilege {
        active: bool,
        message: String,
    },
    SweepBegin,
    Progress {
        phase: String,
        done: usize,
        total: usize,
    },
    Device(DeviceUpdate),
    SweepFinished {
        found: usize,
        elapsed: Duration,
    },
    Error(String),
}

#[derive(Clone)]
pub struct ScanControl {
    pub live: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
    pub interval_secs: Arc<AtomicU64>,
    pub wake: Arc<Notify>,
}

impl ScanControl {
    pub fn new(live: bool, interval_secs: u64) -> Self {
        Self {
            live: Arc::new(AtomicBool::new(live)),
            cancelled: Arc::new(AtomicBool::new(false)),
            interval_secs: Arc::new(AtomicU64::new(interval_secs.max(1))),
            wake: Arc::new(Notify::new()),
        }
    }

    pub fn rescan(&self) {
        self.wake.notify_waiters();
    }

    pub fn quit(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.wake.notify_waiters();
    }

    pub fn set_live(&self, live: bool) {
        self.live.store(live, Ordering::Relaxed);
        self.wake.notify_waiters();
    }
}

pub async fn run_once(
    opts: ScanOptions,
    tx: mpsc::Sender<ScanEvent>,
) -> anyhow::Result<ScanTarget> {
    let target = prepare(&opts, &tx).await?;
    let mdns = mdns::spawn(tx.clone());
    sweep(&target, &tx).await?;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    if let Some(daemon) = mdns {
        let _ = daemon.shutdown();
    }
    Ok(target)
}

pub async fn run_session(
    opts: ScanOptions,
    tx: mpsc::Sender<ScanEvent>,
    control: ScanControl,
) -> anyhow::Result<()> {
    let target = prepare(&opts, &tx).await?;
    let _mdns = mdns::spawn(tx.clone());
    loop {
        if control.cancelled.load(Ordering::Relaxed) {
            break;
        }
        if let Err(err) = sweep(&target, &tx).await {
            let _ = tx.send(ScanEvent::Error(err.to_string())).await;
        }
        if control.cancelled.load(Ordering::Relaxed) {
            break;
        }
        let live = control.live.load(Ordering::Relaxed);
        if live {
            let secs = control.interval_secs.load(Ordering::Relaxed);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = control.wake.notified() => {}
            }
        } else {
            tokio::select! {
                _ = control.wake.notified() => {}
                _ = async {
                    loop {
                        if control.cancelled.load(Ordering::Relaxed) || control.live.load(Ordering::Relaxed) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                } => {}
            }
        }
    }
    Ok(())
}

async fn prepare(opts: &ScanOptions, tx: &mpsc::Sender<ScanEvent>) -> anyhow::Result<ScanTarget> {
    let target =
        iface::resolve(opts.iface.as_deref(), opts.range).context("selecting scan interface")?;
    let active = arp::can_open(&target.pnet_iface);
    let _ = tx
        .send(ScanEvent::Started {
            iface: target.iface_name.clone(),
            prefix: target.scan_network.to_string(),
            local_ipv4: target.ipv4,
            local_mac: target.mac,
            active,
        })
        .await;
    let _ = tx
        .send(ScanEvent::Privilege {
            active,
            message: if active {
                "Active ARP scan.".into()
            } else {
                "Unprivileged fallback: quiet devices may be missing. Re-run with sudo for an ARP sweep."
                    .into()
            },
        })
        .await;
    let _ = tx
        .send(ScanEvent::Device(DeviceUpdate {
            ipv4: Some(target.ipv4),
            ipv6: target.ipv6s.first().copied(),
            mac: target.mac,
            vendor: target.mac.and_then(oui::vendor_for),
            interface: Some(target.iface_name.clone()),
            is_self: true,
            seen: true,
            ..DeviceUpdate::default()
        }))
        .await;
    Ok(target)
}

async fn sweep(target: &ScanTarget, tx: &mpsc::Sender<ScanEvent>) -> anyhow::Result<()> {
    let started = Instant::now();
    let _ = tx.send(ScanEvent::SweepBegin).await;
    let active = arp::can_open(&target.pnet_iface);
    let _ = tx
        .send(ScanEvent::Progress {
            phase: if active { "ARP".into() } else { "ping".into() },
            done: 0,
            total: iface::scan_hosts(target.scan_network).len(),
        })
        .await;

    let ssdp_task = tokio::spawn(ssdp::discover(Duration::from_secs(3)));

    let mut discovered = Vec::new();
    let iface_name = target.iface_name.clone();
    let source_ip = target.ipv4;
    if active {
        let target = target.clone();
        let tx_clone = tx.clone();
        let found = tokio::task::spawn_blocking(move || {
            arp::sweep_sync(&target, |update| {
                let _ = tx_clone.blocking_send(ScanEvent::Device(update));
            })
        })
        .await??;
        discovered = found;
        let _ = tx
            .send(ScanEvent::Progress {
                phase: "ping".into(),
                done: 0,
                total: discovered.len(),
            })
            .await;
        let results = ping::ping_hosts_from(&discovered, Some(source_ip)).await;
        for update in ping::updates_from_results(&results, &iface_name, false) {
            let _ = tx.send(ScanEvent::Device(update)).await;
        }
    } else {
        let hosts = iface::scan_hosts(target.scan_network);
        let _ = tx
            .send(ScanEvent::Progress {
                phase: "ping".into(),
                done: 0,
                total: hosts.len(),
            })
            .await;
        let results = ping::ping_hosts_from(&hosts, Some(source_ip)).await;
        for (ip, rtt) in &results {
            if rtt.is_some() {
                discovered.push(*ip);
            }
        }
        for update in ping::updates_from_results(&results, &target.iface_name, true) {
            let _ = tx.send(ScanEvent::Device(update)).await;
        }
        for update in neighbors::collect(target) {
            if let Some(ip) = update.ipv4 {
                if !discovered.contains(&ip) {
                    discovered.push(ip);
                }
            }
            let _ = tx.send(ScanEvent::Device(update)).await;
        }
    }

    for update in neighbors::collect(target) {
        let _ = tx.send(ScanEvent::Device(update)).await;
    }

    let _ = tx
        .send(ScanEvent::Progress {
            phase: "names".into(),
            done: 0,
            total: discovered.len(),
        })
        .await;

    let dns_task = dns::reverse_many(&discovered);
    let nb_task = netbios::query_many(&discovered);
    let (dns_updates, nb_updates, ssdp_updates) = tokio::join!(dns_task, nb_task, ssdp_task);
    for update in dns_updates {
        let _ = tx.send(ScanEvent::Device(update)).await;
    }
    for update in nb_updates {
        let _ = tx.send(ScanEvent::Device(update)).await;
    }
    if let Ok(updates) = ssdp_updates {
        for update in updates {
            let _ = tx.send(ScanEvent::Device(update)).await;
        }
    }

    let _ = tx
        .send(ScanEvent::SweepFinished {
            found: discovered.len(),
            elapsed: started.elapsed(),
        })
        .await;
    Ok(())
}
