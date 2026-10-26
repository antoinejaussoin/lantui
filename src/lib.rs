pub mod config;
pub mod export;
pub mod model;
pub mod scan;
pub mod tui;

use crate::model::{cmp_devices, ColumnId, Device};
use crate::scan::ScanOptions;
use clap::{Parser, Subcommand};
use ipnetwork::Ipv4Network;
use std::io::{self, Write};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "lantui",
    about = "Scan the local network and inspect hosts in a terminal UI"
)]
pub struct Cli {
    /// Network interface to scan
    #[arg(short, long)]
    pub iface: Option<String>,

    /// IPv4 CIDR to scan instead of the interface prefix
    #[arg(long)]
    pub range: Option<String>,

    /// Keep scanning on an interval
    #[arg(long)]
    pub live: bool,

    /// Live rescan interval in seconds
    #[arg(long, default_value_t = 15)]
    pub interval: u64,

    /// Disable colour even when the terminal supports it
    #[arg(long)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run one scan and print JSON or CSV
    Scan {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        csv: bool,
        #[arg(short, long)]
        iface: Option<String>,
        #[arg(long)]
        range: Option<String>,
    },
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Scan {
            json,
            csv,
            iface,
            range,
        }) => {
            let opts = options(
                iface.or(cli.iface),
                range.or(cli.range),
                false,
                cli.interval,
            )?;
            run_scan_cmd(opts, json, csv).await
        }
        None => {
            let opts = options(cli.iface, cli.range, cli.live, cli.interval)?;
            let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none();
            tui::run(opts, color).await
        }
    }
}

fn options(
    iface: Option<String>,
    range: Option<String>,
    live: bool,
    interval: u64,
) -> anyhow::Result<ScanOptions> {
    let range = match range {
        Some(raw) => Some(raw.parse::<Ipv4Network>()?),
        None => None,
    };
    Ok(ScanOptions {
        iface,
        range,
        live,
        interval: Duration::from_secs(interval.max(1)),
    })
}

async fn run_scan_cmd(opts: ScanOptions, json: bool, csv: bool) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let worker = tokio::spawn(async move { crate::scan::run_once(opts, tx).await });
    let mut store = crate::model::DeviceStore::new();
    store.begin_sweep();
    let collect = async {
        while let Some(event) = rx.recv().await {
            match event {
                crate::scan::ScanEvent::Device(update) => {
                    let _ = store.apply(update);
                }
                crate::scan::ScanEvent::Error(err) => eprintln!("{err}"),
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(45), collect)
        .await
        .ok();
    store.finish_sweep();
    let _ = worker.await?;

    let mut devices: Vec<&Device> = store.iter().collect();
    devices.sort_by(|a, b| cmp_devices(a, b, ColumnId::Ipv4, true));
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if csv {
        export::write_csv(&devices, &mut handle)?;
    } else if json {
        export::write_json(&devices, &mut handle)?;
        writeln!(handle)?;
    } else {
        writeln!(
            handle,
            "{:<4} {:<15} {:<17} {:<22} {:<16} {:<8} mDNS",
            "ST", "IPv4", "MAC", "Hostname", "Vendor", "Ping"
        )?;
        for device in devices {
            writeln!(
                handle,
                "{:<4} {:<15} {:<17} {:<22} {:<16} {:<8} {}",
                device.field(ColumnId::Status),
                trunc(&device.field(ColumnId::Ipv4), 15),
                trunc(&device.field(ColumnId::Mac), 17),
                trunc(&device.field(ColumnId::Hostname), 22),
                trunc(&device.field(ColumnId::Vendor), 16),
                trunc(&device.field(ColumnId::Ping), 8),
                device.field(ColumnId::Mdns)
            )?;
        }
    }
    Ok(())
}

fn trunc(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_string()
    } else {
        let mut s: String = value.chars().take(width.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}
