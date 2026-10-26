use super::app::{App, Mode};
use crate::model::{columns_fit_width, ColumnId, Device};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use ratatui::Frame;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(frame.area());

    frame.render_widget(status_line(app), chunks[0]);
    frame.render_widget(filter_line(app), chunks[1]);
    draw_table(frame, app, chunks[2]);
    frame.render_widget(detail_pane(app), chunks[3]);
    frame.render_widget(help_line(app), chunks[4]);

    match app.mode {
        Mode::Columns => draw_columns(frame, app),
        Mode::Help => draw_help(frame, app),
        Mode::Iface => draw_iface(frame, app),
        Mode::Comment => draw_comment(frame, app),
        _ => {}
    }
}

fn style(app: &App, color: Color) -> Style {
    if app.color {
        Style::default().fg(color)
    } else {
        Style::default()
    }
}

fn status_line(app: &App) -> Paragraph<'static> {
    let mode = match app.active {
        Some(true) => "ARP",
        Some(false) => "fallback",
        None => "…",
    };
    let live = if app.live {
        format!("live {}s", app.config.live_interval_secs)
    } else {
        "oneshot".into()
    };
    let shown = app.view_keys().len();
    let total = app.store.len();
    let sweep = app
        .last_sweep
        .map(|d| format!("{:.1}s", d.as_secs_f32()))
        .unwrap_or_else(|| "—".into());
    let phase = if app.phase.is_empty() {
        String::new()
    } else {
        format!("  {}", app.phase)
    };
    let text = format!(
        " lantui  {}  {}  {}  {shown}/{total} hosts  {live}  last {sweep}{phase}  {}",
        app.iface, app.prefix, mode, app.status
    );
    Paragraph::new(text).style(style(app, Color::Cyan))
}

fn filter_line(app: &App) -> Paragraph<'static> {
    let prefix = if app.mode == Mode::Filter { "/" } else { " " };
    let text = if app.filter.is_empty() && app.mode != Mode::Filter {
        format!(
            " {prefix}  {}",
            if app.hide_offline {
                "hiding offline"
            } else {
                "filter off"
            }
        )
    } else {
        format!(" {prefix} {}", app.filter)
    };
    Paragraph::new(text).style(style(app, Color::Yellow))
}

fn help_line(app: &App) -> Paragraph<'static> {
    let text = match app.mode {
        Mode::Columns => " space toggle  J/K reorder  enter close",
        Mode::Filter => " type to filter  enter keep  esc clear",
        Mode::Comment => " type comment  enter save  esc cancel",
        Mode::Iface => " j/k select  enter switch  esc cancel",
        Mode::Help => " esc close",
        Mode::Normal => {
            " j/k move  / filter  c columns  s sort  l live  r rescan  o offline  p ports  n note  e csv  y/Y copy  i iface  ? help  q quit"
        }
    };
    Paragraph::new(text).style(style(app, Color::DarkGray))
}

fn draw_table(frame: &mut Frame, app: &App, area: Rect) {
    let inner_width = area.width.saturating_sub(2);
    let wanted = app.wanted_columns();
    let cols = app.display_columns(inner_width);
    if cols.is_empty() {
        frame.render_widget(Paragraph::new(" no columns visible"), area);
        return;
    }
    let hidden = wanted.len().saturating_sub(cols.len());
    let headers = Row::new(cols.iter().map(|c| {
        let mut title = c.title().to_string();
        if *c == app.config.sort_column {
            title.push(if app.config.sort_asc { '↑' } else { '↓' });
        }
        Cell::from(title)
    }))
    .style(style(app, Color::Blue).add_modifier(if app.color {
        Modifier::BOLD
    } else {
        Modifier::empty()
    }));

    let keys = app.view_keys();
    let rows = keys.iter().enumerate().filter_map(|(idx, key)| {
        let device = app.store.get(key)?;
        let mut row_style = row_style(app, device);
        if idx == app.selected {
            row_style = row_style.add_modifier(Modifier::REVERSED);
        }
        let cells = cols.iter().map(|col| Cell::from(cell_text(device, *col)));
        Some(Row::new(cells).style(row_style))
    });

    let mut widths: Vec<Constraint> = cols.iter().map(|c| Constraint::Length(c.width())).collect();
    let used = columns_fit_width(&cols);
    if inner_width > used {
        let extra = inner_width - used;
        let grow = cols
            .iter()
            .position(|c| *c == ColumnId::Hostname)
            .or_else(|| cols.iter().position(|c| *c == ColumnId::Vendor))
            .unwrap_or(cols.len() - 1);
        widths[grow] = Constraint::Length(cols[grow].width() + extra);
    }

    let mut block = Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::TOP);
    if hidden == 1 {
        block = block.title(" 1 col hidden ");
    } else if hidden > 1 {
        block = block.title(format!(" {hidden} cols hidden "));
    }
    let table = Table::new(rows, widths)
        .header(headers)
        .block(block)
        .column_spacing(1);
    frame.render_widget(table, area);
}

fn cell_text(device: &Device, col: ColumnId) -> String {
    if col == ColumnId::Status {
        let mark = if device.is_self {
            "me"
        } else if device.online {
            if device.new_this_sweep {
                "*up"
            } else {
                "up"
            }
        } else {
            "dn"
        };
        return mark.to_string();
    }
    device.field(col)
}

fn row_style(app: &App, device: &Device) -> Style {
    if !app.color {
        return Style::default();
    }
    if device.is_self {
        return Style::default().fg(Color::Cyan);
    }
    if device.new_this_sweep {
        return Style::default().fg(Color::Yellow);
    }
    if !device.online {
        return Style::default().fg(Color::DarkGray);
    }
    if let Some(ms) = device.ping_ms {
        if ms < 10.0 {
            return Style::default().fg(Color::Green);
        }
        if ms < 50.0 {
            return Style::default().fg(Color::Yellow);
        }
        return Style::default().fg(Color::Red);
    }
    Style::default().fg(Color::Green)
}

fn detail_pane(app: &App) -> Paragraph<'static> {
    let block = Block::default().title(" details ").borders(Borders::ALL);
    let Some(device) = app.selected_device() else {
        return Paragraph::new(" no host selected").block(block);
    };
    let ports = if device.open_ports.is_empty() {
        "—".into()
    } else {
        device
            .open_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let extras = {
        let mut parts = Vec::new();
        for ip in &device.extra_ipv4 {
            parts.push(ip.to_string());
        }
        for ip in &device.extra_ipv6 {
            parts.push(ip.to_string());
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("  extra {}", parts.join(", "))
        }
    };
    let lines = vec![
        Line::from(format!(
            " IPv4 {}   IPv6 {} / {}   MAC {}   {}",
            opt(&device.ipv4),
            opt(&device.ipv6_ll),
            opt(&device.ipv6_global),
            opt(&device.mac),
            if device.online { "online" } else { "offline" }
        )),
        Line::from(format!(
            " hostname {}   vendor {}   model {}   ping {}",
            blank(&device.hostname()),
            blank(&device.vendor),
            opt(&device.model),
            device
                .ping_ms
                .map(|ms| format!("{ms:.1}ms"))
                .unwrap_or_else(|| "—".into())
        )),
        Line::from(format!(
            " DNS {}   mDNS {}   SMB {} ({})",
            opt(&device.dns_name),
            opt(&device.mdns_name),
            opt(&device.smb_name),
            opt(&device.smb_domain)
        )),
        Line::from(format!(
            " services {}   ports {ports}   iface {}{extras}",
            if device.services.is_empty() {
                "—".into()
            } else {
                device.services.join(", ")
            },
            opt(&device.interface)
        )),
        Line::from(format!(
            " comment {}   last {}",
            opt(&device.comment),
            opt(&device.last_seen.map(|t| t.format("%H:%M:%S").to_string()))
        )),
        Line::from(Span::styled(
            format!(" {}", app.privilege_msg),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    Paragraph::new(lines).block(block)
}

fn opt<T: ToString>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map(ToString::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "—".into())
}

fn blank(value: &str) -> String {
    if value.is_empty() {
        "—".into()
    } else {
        value.to_string()
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn draw_columns(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 42, 22);
    frame.render_widget(Clear, area);
    let lines: Vec<Line> = app
        .config
        .columns
        .iter()
        .enumerate()
        .map(|(idx, col)| {
            let mark = if col.visible { "[x]" } else { "[ ]" };
            let mut line = format!(" {mark} {}", col.id.title());
            if idx == app.column_cursor {
                line.insert(0, '>');
            } else {
                line.insert(0, ' ');
            }
            Line::from(line)
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title(" columns ").borders(Borders::ALL)),
        area,
    );
}

fn draw_help(frame: &mut Frame, _app: &App) {
    let area = centered(frame.area(), 70, 20);
    frame.render_widget(Clear, area);
    let text = "\
 lantui — LAN scanner

 j / k or arrows   move
 g / G             top / bottom
 /                 filter (esc clears)
 c                 show / hide / reorder columns
 s / S             cycle sort column / reverse
                   extra columns hide when the terminal is narrow
 l                 live mode
 r                 rescan
 o                 hide offline hosts
 p                 probe common ports on the selected host
 n                 edit comment
 e                 export filtered rows as CSV
 y / Y             copy IPv4 / MAC
 i                 pick interface
 q                 quit

 Active ARP needs sudo (raw / BPF socket). Without it, lantui
 pings the subnet and reads the neighbor cache.";
    frame.render_widget(
        Paragraph::new(text).block(Block::default().title(" help ").borders(Borders::ALL)),
        area,
    );
}

fn draw_iface(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 50, 16);
    frame.render_widget(Clear, area);
    let lines: Vec<Line> = app
        .iface_list
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let prefix = if idx == app.iface_cursor { "> " } else { "  " };
            Line::from(format!("{prefix}{name}"))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title(" interface ").borders(Borders::ALL)),
        area,
    );
}

fn draw_comment(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 50, 5);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(format!(" {}", app.comment_buf))
            .block(Block::default().title(" comment ").borders(Borders::ALL)),
        area,
    );
}
