pub mod app;
pub mod render;

use crate::scan::{ScanControl, ScanEvent, ScanOptions};
use anyhow::Context;
use app::{Action, App, Mode};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{stdout, Stdout};
use std::panic;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run(opts: ScanOptions, color: bool) -> anyhow::Result<()> {
    let mut app = App::new(opts.clone(), color);
    let (tx, mut rx) = mpsc::channel::<ScanEvent>(1024);
    app.live = opts.live;
    let mut control = ScanControl::new(opts.live, app.config.live_interval_secs);
    let mut scan = tokio::spawn(crate::scan::run_session(
        opts.clone(),
        tx.clone(),
        control.clone(),
    ));

    let mut terminal = setup()?;
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(80));

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(event) => app.apply_scan(event),
                    None => app.status = "scanner stopped".into(),
                }
            }
            event = events.next() => {
                if let Some(Ok(Event::Key(key))) = event {
                    if key.kind == KeyEventKind::Press {
                        match app.handle_key(key, &control) {
                            Action::Quit => break,
                            Action::Rescan => control.rescan(),
                            Action::RestartScan(new_opts) => {
                                control.quit();
                                scan.abort();
                                let _ = scan.await;
                                control = ScanControl::new(new_opts.live, app.config.live_interval_secs);
                                app.opts = new_opts.clone();
                                app.store = crate::model::DeviceStore::new();
                                scan = tokio::spawn(crate::scan::run_session(
                                    new_opts,
                                    tx.clone(),
                                    control.clone(),
                                ));
                            }
                            Action::Probe => {
                                probe_selected(&mut app).await;
                            }
                            Action::None => {}
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                terminal.draw(|frame| render::draw(frame, &app))?;
            }
        }
    }

    control.quit();
    scan.abort();
    restore(&mut terminal)?;
    if let Err(err) = app.config.save() {
        eprintln!("could not save config: {err}");
    }
    if let Err(err) = app.labels.save() {
        eprintln!("could not save labels: {err}");
    }
    Ok(())
}

async fn probe_selected(app: &mut App) {
    let Some(ip) = app.selected_ip() else {
        return;
    };
    app.status = format!("probing {ip}…");
    let ports = crate::scan::ports::probe(ip).await;
    app.apply_scan(ScanEvent::Device(crate::model::DeviceUpdate {
        ipv4: ip.is_ipv4().then(|| match ip {
            std::net::IpAddr::V4(v) => v,
            _ => unreachable!(),
        }),
        ipv6: ip.is_ipv6().then(|| match ip {
            std::net::IpAddr::V6(v) => v,
            _ => unreachable!(),
        }),
        mac: app.selected_mac(),
        open_ports: Some(ports.clone()),
        ..crate::model::DeviceUpdate::default()
    }));
    app.status = if ports.is_empty() {
        format!("no common ports open on {ip}")
    } else {
        format!(
            "open on {ip}: {}",
            ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
}

fn setup() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    install_panic_hook();
    Ok(Terminal::new(CrosstermBackend::new(out))?)
}

fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn install_panic_hook() {
    let original = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, LeaveAlternateScreen);
        original(info);
    }));
}

impl App {
    pub fn handle_key(&mut self, key: KeyEvent, control: &ScanControl) -> Action {
        match self.mode {
            Mode::Filter => self.handle_filter(key),
            Mode::Columns => self.handle_columns(key),
            Mode::Help => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')
                ) {
                    self.mode = Mode::Normal;
                }
                Action::None
            }
            Mode::Comment => self.handle_comment(key),
            Mode::Iface => self.handle_iface(key),
            Mode::Normal => self.handle_normal(key, control),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent, control: &ScanControl) -> Action {
        match key.code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_sel(1);
                Action::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_sel(-1);
                Action::None
            }
            KeyCode::Char('g') => {
                self.selected = 0;
                Action::None
            }
            KeyCode::Char('G') => {
                self.selected = self.view_keys().len().saturating_sub(1);
                Action::None
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
                Action::None
            }
            KeyCode::Esc => {
                self.filter.clear();
                Action::None
            }
            KeyCode::Char('c') => {
                self.column_cursor = 0;
                self.mode = Mode::Columns;
                Action::None
            }
            KeyCode::Char('s') => {
                self.cycle_sort();
                Action::None
            }
            KeyCode::Char('S') => {
                self.config.sort_asc = !self.config.sort_asc;
                Action::None
            }
            KeyCode::Char('l') => {
                self.live = !self.live;
                control.set_live(self.live);
                self.status = if self.live {
                    format!("live every {}s", self.config.live_interval_secs)
                } else {
                    "live off".into()
                };
                Action::None
            }
            KeyCode::Char('r') => {
                self.status = "rescanning…".into();
                Action::Rescan
            }
            KeyCode::Char('o') => {
                self.hide_offline = !self.hide_offline;
                Action::None
            }
            KeyCode::Char('p') => Action::Probe,
            KeyCode::Char('n') => {
                self.comment_buf = self
                    .selected_device()
                    .and_then(|d| d.comment.clone())
                    .unwrap_or_default();
                self.mode = Mode::Comment;
                Action::None
            }
            KeyCode::Char('e') => {
                self.export_csv();
                Action::None
            }
            KeyCode::Char('y') => {
                self.copy_field(false);
                Action::None
            }
            KeyCode::Char('Y') => {
                self.copy_field(true);
                Action::None
            }
            KeyCode::Char('i') => {
                self.iface_list = crate::scan::iface::list_ifaces()
                    .into_iter()
                    .filter(|i| !i.loopback)
                    .map(|i| {
                        format!(
                            "{}  {}",
                            i.name,
                            i.ipv4
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "-".into())
                        )
                    })
                    .collect();
                self.iface_cursor = 0;
                self.mode = Mode::Iface;
                Action::None
            }
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_filter(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => self.mode = Mode::Normal,
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.push(c);
            }
            _ => {}
        }
        Action::None
    }

    fn handle_columns(&mut self, key: KeyEvent) -> Action {
        let len = self.config.columns.len();
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('c') | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.column_cursor = (self.column_cursor + 1).min(len.saturating_sub(1));
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.column_cursor = self.column_cursor.saturating_sub(1);
            }
            KeyCode::Char(' ') => {
                let only_one = self.config.visible_columns().len() == 1;
                if let Some(col) = self.config.columns.get_mut(self.column_cursor) {
                    if col.visible && only_one {
                        self.status = "keep at least one column".into();
                    } else {
                        col.visible = !col.visible;
                    }
                }
            }
            KeyCode::Char('J') => {
                if self.column_cursor + 1 < len {
                    self.config
                        .columns
                        .swap(self.column_cursor, self.column_cursor + 1);
                    self.column_cursor += 1;
                }
            }
            KeyCode::Char('K') if self.column_cursor > 0 => {
                self.config
                    .columns
                    .swap(self.column_cursor, self.column_cursor - 1);
                self.column_cursor -= 1;
            }
            _ => {}
        }
        Action::None
    }

    fn handle_comment(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => {
                self.save_comment();
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                self.comment_buf.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.comment_buf.push(c);
            }
            _ => {}
        }
        Action::None
    }

    fn handle_iface(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
                Action::None
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.iface_cursor =
                    (self.iface_cursor + 1).min(self.iface_list.len().saturating_sub(1));
                Action::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.iface_cursor = self.iface_cursor.saturating_sub(1);
                Action::None
            }
            KeyCode::Enter => {
                if let Some(line) = self.iface_list.get(self.iface_cursor) {
                    let name = line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    self.mode = Mode::Normal;
                    self.status = format!("scanning {name}");
                    let mut opts = self.opts.clone();
                    opts.iface = Some(name);
                    opts.live = self.live;
                    return Action::RestartScan(opts);
                }
                Action::None
            }
            _ => Action::None,
        }
    }
}
