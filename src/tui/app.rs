use crate::config::{AppConfig, Labels};
use crate::export;
use crate::model::{
    cmp_devices, fit_columns, ColumnId, Device, DeviceKey, DeviceStore, DeviceUpdate, MacAddr,
};
use crate::scan::{ScanEvent, ScanOptions};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
    Columns,
    Help,
    Comment,
    Iface,
}

#[derive(Debug)]
pub enum Action {
    None,
    Quit,
    Rescan,
    RestartScan(ScanOptions),
    Probe,
}

pub struct App {
    pub store: DeviceStore,
    pub config: AppConfig,
    pub labels: Labels,
    pub opts: ScanOptions,
    pub iface: String,
    pub prefix: String,
    pub local_ipv4: String,
    pub active: Option<bool>,
    pub privilege_msg: String,
    pub phase: String,
    pub progress: (usize, usize),
    pub filter: String,
    pub mode: Mode,
    pub selected: usize,
    pub live: bool,
    pub hide_offline: bool,
    pub status: String,
    pub last_sweep: Option<Duration>,
    pub color: bool,
    pub column_cursor: usize,
    pub comment_buf: String,
    pub iface_list: Vec<String>,
    pub iface_cursor: usize,
    pub sweeping: bool,
}

impl App {
    pub fn new(opts: ScanOptions, color: bool) -> Self {
        let config = AppConfig::load();
        let labels = Labels::load();
        Self {
            store: DeviceStore::new(),
            live: opts.live,
            opts,
            config,
            labels,
            iface: String::new(),
            prefix: String::new(),
            local_ipv4: String::new(),
            active: None,
            privilege_msg: String::new(),
            phase: String::new(),
            progress: (0, 0),
            filter: String::new(),
            mode: Mode::Normal,
            selected: 0,
            hide_offline: false,
            status: "starting…".into(),
            last_sweep: None,
            color,
            column_cursor: 0,
            comment_buf: String::new(),
            iface_list: Vec::new(),
            iface_cursor: 0,
            sweeping: false,
        }
    }

    pub fn apply_scan(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started {
                iface,
                prefix,
                local_ipv4,
                active,
                ..
            } => {
                self.iface = iface;
                self.prefix = prefix;
                self.local_ipv4 = local_ipv4.to_string();
                self.active = Some(active);
            }
            ScanEvent::Privilege { active, message } => {
                self.active = Some(active);
                self.privilege_msg = message;
            }
            ScanEvent::SweepBegin => {
                self.store.begin_sweep();
                self.sweeping = true;
                self.status = "scanning…".into();
            }
            ScanEvent::Progress { phase, done, total } => {
                self.phase = phase;
                self.progress = (done, total);
            }
            ScanEvent::Device(update) => {
                self.apply_update(update);
            }
            ScanEvent::SweepFinished { found, elapsed } => {
                self.store.finish_sweep();
                self.sweeping = false;
                self.last_sweep = Some(elapsed);
                self.phase.clear();
                self.status = format!("sweep done · {found} hosts · {:.1}s", elapsed.as_secs_f32());
            }
            ScanEvent::Error(err) => {
                self.status = err;
                self.sweeping = false;
            }
        }
        self.clamp_selected();
    }

    fn apply_update(&mut self, mut update: DeviceUpdate) {
        if let Some(mac) = update.mac {
            if update.comment.is_none() {
                if let Some(comment) = self.labels.get(&mac.to_string()) {
                    update.comment = Some(comment.to_string());
                }
            }
        } else if let Some(ip) = update.ipv4 {
            let key = format!("ipv4:{ip}");
            if update.comment.is_none() {
                if let Some(comment) = self.labels.get(&key) {
                    update.comment = Some(comment.to_string());
                }
            }
        }
        let _ = self.store.apply(update);
    }

    pub fn view_keys(&self) -> Vec<DeviceKey> {
        let mut devices: Vec<&Device> = self
            .store
            .iter()
            .filter(|d| !self.hide_offline || d.online || d.is_self)
            .filter(|d| d.matches(&self.filter))
            .collect();
        devices.sort_by(|a, b| cmp_devices(a, b, self.config.sort_column, self.config.sort_asc));
        devices.into_iter().filter_map(Device::key).collect()
    }

    pub fn selected_device(&self) -> Option<&Device> {
        let key = self.view_keys().get(self.selected)?.clone();
        self.store.get(&key)
    }

    pub fn selected_key(&self) -> Option<DeviceKey> {
        self.view_keys().get(self.selected).cloned()
    }

    pub fn selected_ip(&self) -> Option<IpAddr> {
        self.selected_device().and_then(Device::primary_ip)
    }

    pub fn selected_mac(&self) -> Option<MacAddr> {
        self.selected_device().and_then(|d| d.mac)
    }

    pub fn move_sel(&mut self, delta: isize) {
        let len = self.view_keys().len() as isize;
        if len == 0 {
            self.selected = 0;
            return;
        }
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }

    pub fn clamp_selected(&mut self) {
        let len = self.view_keys().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn cycle_sort(&mut self) {
        let visible = self.config.visible_columns();
        if visible.is_empty() {
            return;
        }
        let idx = visible
            .iter()
            .position(|col| *col == self.config.sort_column)
            .map(|i| (i + 1) % visible.len())
            .unwrap_or(0);
        self.config.sort_column = visible[idx];
    }

    pub fn wanted_columns(&self) -> Vec<ColumnId> {
        self.config.visible_columns()
    }

    pub fn display_columns(&self, inner_width: u16) -> Vec<ColumnId> {
        fit_columns(self.wanted_columns(), inner_width)
    }

    pub fn save_comment(&mut self) {
        let (mac, ipv4) = match self.selected_device() {
            Some(device) => (device.mac, device.ipv4),
            None => return,
        };
        let key = mac
            .map(|m| m.to_string())
            .or_else(|| ipv4.map(|ip| format!("ipv4:{ip}")));
        let Some(key) = key else {
            self.status = "no MAC or IPv4 to attach a comment".into();
            return;
        };
        let comment = self.comment_buf.trim().to_string();
        self.labels.set(key, comment.clone());
        if let Some(mac) = mac {
            self.apply_update(DeviceUpdate {
                mac: Some(mac),
                ipv4,
                comment: Some(comment),
                ..DeviceUpdate::default()
            });
        } else if let Some(ip) = ipv4 {
            self.apply_update(DeviceUpdate {
                ipv4: Some(ip),
                comment: Some(comment),
                ..DeviceUpdate::default()
            });
        }
        let _ = self.labels.save();
        self.status = "comment saved".into();
    }

    pub fn copy_field(&mut self, mac: bool) {
        let Some(device) = self.selected_device() else {
            return;
        };
        let text = if mac {
            device.mac.map(|m| m.to_string())
        } else {
            device.ipv4.map(|ip| ip.to_string())
        };
        let Some(text) = text else {
            self.status = "nothing to copy".into();
            return;
        };
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.clone())) {
            Ok(()) => self.status = format!("copied {text}"),
            Err(err) => self.status = format!("clipboard: {err}"),
        }
    }

    pub fn export_csv(&mut self) {
        let keys = self.view_keys();
        let devices: Vec<&Device> = keys.iter().filter_map(|k| self.store.get(k)).collect();
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let path = format!("lantui-{stamp}.csv");
        match std::fs::File::create(&path) {
            Ok(file) => match export::write_csv(&devices, file) {
                Ok(()) => self.status = format!("wrote {path}"),
                Err(err) => self.status = format!("export: {err}"),
            },
            Err(err) => self.status = format!("export: {err}"),
        }
    }
}
