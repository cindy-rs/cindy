//! Live per-host run view.
//!
//! Each deployment future reports into an mpsc channel: stderr lines and
//! the final status (derived purely from why its stdio closed — no special
//! wire protocol). When stderr is a tty we draw a two-pane TUI (host list +
//! selected host's output). Quitting the TUI while hosts are still running
//! aborts the play: the `abort` channel is flipped on exit and `main` tears
//! the deployments down. When stderr isn't a tty (CI, pipe, `> log`), we
//! fall back to today's prefixed line-stream so nothing about
//! non-interactive use changes.

use std::io::IsTerminal as _;

use crossterm::event::EventStream;
use futures_util::StreamExt as _;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};

use std::sync::{Mutex, OnceLock};

/// Width of the host-list pane, as a percentage of the terminal. Used both
/// for the layout split and the mouse hit-test, so they can't drift apart.
const LIST_PCT: u16 = 30;

/// Braille spinner frames for hosts (and phases) that are still running.
/// Advanced by the render tick, so a busy host visibly *moves*.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Per-host retained output lines. A chatty host streaming for hours
/// would otherwise grow the pane (and its per-frame re-render) without
/// bound; the oldest lines are evicted past this point.
const MAX_LINES: usize = 10_000;

/// Compact human-readable duration: `9.3s` under a minute, `4m07s` beyond.
fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{}m{:02}s", secs / 60, secs % 60)
    }
}

/// Shared sink for the CLI's own `tracing` output so it can be shown in a
/// pane instead of corrupting the alternate screen. Lines accumulate here;
/// the TUI reads them each frame.
static LOG: OnceLock<Mutex<LogBuffer>> = OnceLock::new();

/// The retained log lines plus how many were evicted past
/// [`MAX_LINES`] — the same cap and eviction policy as the host panes,
/// for the same reason: a chatty process streaming for hours must not
/// grow the pane (and its per-frame re-render) without bound. The
/// dropped count keeps the pane title truthful about what was lost.
#[derive(Default)]
struct LogBuffer {
    lines: Vec<String>,
    dropped: usize,
}

impl LogBuffer {
    fn push(&mut self, line: String) {
        self.lines.push(line);
        let excess = self.lines.len().saturating_sub(MAX_LINES);
        if excess > 0 {
            self.lines.drain(..excess);
            self.dropped += excess;
        }
    }
}

fn log_buffer() -> &'static Mutex<LogBuffer> {
    LOG.get_or_init(|| Mutex::new(LogBuffer::default()))
}

/// A `tracing_subscriber` writer that appends formatted log lines to the
/// shared buffer (one entry per write, trimmed of the trailing newline).
pub struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        let line = s.trim_end_matches('\n');
        if !line.is_empty() {
            // Recover a poisoned lock rather than panicking: this is a
            // logging path, and the buffer can't be half-updated by a
            // panic — the data inside is still exactly what was pushed.
            log_buffer()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line.to_owned());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogWriter
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Finished,
    Failed,
}

impl Status {
    fn color(self) -> Color {
        match self {
            Status::Running => Color::Yellow,
            Status::Finished => Color::Green,
            Status::Failed => Color::Red,
        }
    }
    fn glyph(self) -> &'static str {
        match self {
            Status::Running => "•",
            Status::Finished => "✓",
            Status::Failed => "✗",
        }
    }
}

/// Which process a captured line came from. Rendered in different colours
/// so orchestrator (local) and worker (remote) output are distinguishable.
#[derive(Clone, Copy)]
pub enum Source {
    Orchestrator,
    Worker,
}

/// A message from `main`/a deployment future to the progress view.
pub enum Msg {
    /// Register a host in the list. Hosts are appended in send order, so the
    /// nth `AddHost` is host `idx == n`, matching the `idx` later carried by
    /// `Line`/`Status`. Sent once discovery knows the targets — the view is
    /// already on screen before this arrives (showing the log pane).
    AddHost { name: String, tags: Vec<String> },
    /// One stderr line from host `idx`, tagged with its source.
    Line(usize, Source, String),
    /// Host `idx` reached a terminal state.
    Status(usize, Status),
    /// Tear the view down now, without waiting for the user to quit.
    /// Sent when the run aborts on an infrastructure error (SSH
    /// discovery, compile, …) before hosts produced anything worth
    /// inspecting — the error must land on the real terminal, not sit
    /// behind an idle TUI that looks stuck.
    Shutdown,
}

struct Host {
    name: String,
    tags: Vec<String>,
    status: Status,
    lines: Vec<(Source, String)>,
    /// Lines evicted from `lines` once it hit [`MAX_LINES`]; the output
    /// title reports `dropped + lines.len()` so the count stays truthful.
    dropped: usize,
    /// When the host appeared in the view (its deployment started).
    started: std::time::Instant,
    /// Total runtime, frozen at the moment a terminal status arrived.
    /// `None` while still running — render `started.elapsed()` live.
    elapsed: Option<std::time::Duration>,
}

impl Host {
    /// The runtime to display: frozen for finished/failed hosts, live
    /// (still counting) for running ones.
    fn runtime(&self) -> std::time::Duration {
        self.elapsed.unwrap_or_else(|| self.started.elapsed())
    }

    fn set_status(&mut self, status: Status) {
        self.status = status;
        if status != Status::Running && self.elapsed.is_none() {
            self.elapsed = Some(self.started.elapsed());
        }
    }

    fn push_line(&mut self, src: Source, line: String) {
        self.lines.push((src, line));
        let excess = self.lines.len().saturating_sub(MAX_LINES);
        if excess > 0 {
            self.lines.drain(..excess);
            self.dropped += excess;
        }
    }
}

/// Host tallies per status, shared by the list title and the legend.
#[derive(Default)]
struct Counts {
    running: usize,
    done: usize,
    failed: usize,
}

impl Counts {
    fn of(hosts: &[Host]) -> Self {
        let mut c = Counts::default();
        for h in hosts {
            match h.status {
                Status::Running => c.running += 1,
                Status::Finished => c.done += 1,
                Status::Failed => c.failed += 1,
            }
        }
        c
    }
}

/// Output-pane scroll position for the selected host.
#[derive(Default)]
struct OutputScroll {
    /// Lines *above* the live tail: 0 follows the newest output, larger
    /// values scroll back into history.
    vert: u16,
    /// Columns panned right, for long lines (wide diffs etc.). Clamped to the
    /// widest visible line in `draw_output`.
    horiz: u16,
}

/// Render messages from `rx`. The host list starts empty and grows as
/// `Msg::AddHost`s arrive, so the view can be shown immediately — during the
/// (potentially slow) compile/discovery phase the log pane already reflects
/// the CLI's `tracing` output, so it never looks frozen. Returns when the
/// user quits (tty) or the channel closes after all hosts finish (non-tty).
pub async fn run(
    rx: tokio::sync::mpsc::UnboundedReceiver<Msg>,
    abort: tokio::sync::watch::Sender<bool>,
) {
    if std::io::stderr().is_terminal() {
        if let Err(e) = tui(rx, abort).await {
            eprintln!("progress view error: {e:?}");
        }
    } else {
        stream(rx).await;
    }
}

fn add_host(hosts: &mut Vec<Host>, name: String, tags: Vec<String>) {
    hosts.push(Host {
        name,
        tags,
        status: Status::Running,
        lines: Vec::new(),
        dropped: 0,
        started: std::time::Instant::now(),
        elapsed: None,
    });
}

/// Non-interactive fallback: prefix every line with its host and print it.
/// The loop ends on its own when every sender is dropped (all hosts done).
/// This path only runs when stderr is not a tty, so it emits no ANSI of
/// its own and strips escape codes from child output — raw escapes in a
/// piped log/CI capture are noise.
async fn stream(mut rx: tokio::sync::mpsc::UnboundedReceiver<Msg>) {
    let mut hosts: Vec<Host> = Vec::new();
    while let Some(msg) = rx.recv().await {
        match msg {
            Msg::AddHost { name, tags } => add_host(&mut hosts, name, tags),
            Msg::Line(idx, _src, line) => {
                eprintln!("[{}] {}", hosts[idx].name, strip_ansi(&line));
            }
            Msg::Status(idx, status) => {
                hosts[idx].status = status;
                let label = match status {
                    Status::Finished => "finished",
                    Status::Failed => "failed",
                    Status::Running => continue,
                };
                eprintln!("[{}] {label}", hosts[idx].name);
            }
            // Non-interactive output has nothing to tear down; the loop
            // ends when the senders drop right after this message.
            Msg::Shutdown => break,
        }
    }
}

/// Render a possibly-ANSI-styled string back to plain text.
fn strip_ansi(s: &str) -> String {
    use ansi_to_tui::IntoText as _;
    match s.into_text() {
        Ok(text) => text
            .lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|sp| sp.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(_) => s.to_owned(),
    }
}

async fn tui(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Msg>,
    abort: tokio::sync::watch::Sender<bool>,
) -> eyre::Result<()> {
    enable_raw_mode()?;
    execute!(std::io::stderr(), EnterAlternateScreen, EnableMouseCapture)?;

    let mut hosts: Vec<Host> = Vec::new();
    let result = tui_loop(&mut hosts, &mut rx, &abort).await;

    let _ = disable_raw_mode();
    let _ = execute!(std::io::stderr(), DisableMouseCapture, LeaveAlternateScreen);

    result
}

async fn tui_loop(
    hosts: &mut Vec<Host>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Msg>,
    abort: &tokio::sync::watch::Sender<bool>,
) -> eyre::Result<()> {
    let backend = CrosstermBackend::new(std::io::stderr());
    let mut terminal = Terminal::new(backend)?;
    let mut events = EventStream::new();

    let mut selected = 0usize;
    let mut list_state = ListState::default();
    let mut confirm_quit = false;
    // Output-pane scroll (vertical tail-offset + horizontal pan) for the
    // selected host. Switching hosts resets it to the tail, column 0.
    let mut scroll = OutputScroll::default();
    // Once every host future has dropped its sender the channel closes; we
    // stop selecting on it (otherwise the closed branch is always ready and
    // would starve input handling), but keep the view up until the user quits.
    let mut channel_open = true;
    // Height of the bottom CLI-log pane, resizable with `+`/`-`.
    let mut log_height: u16 = 6;
    // Render tick: messages and input already trigger a redraw, but the
    // cli-log pane fills through a side buffer (no message), spinners
    // animate, and running hosts' clocks advance — without a tick the
    // view sits frozen through the whole compile/discovery phase.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(120));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut frame: usize = 0;

    loop {
        list_state.select(Some(selected));
        let view = View {
            selected,
            confirm_quit,
            log_height,
            spinner: SPINNER[frame % SPINNER.len()],
        };
        // `draw` clamps `scroll` against the output pane's real height (the
        // only place that height is known), keeping the two in sync.
        terminal.draw(|f| draw(f, hosts, &mut list_state, &mut scroll, &view))?;

        tokio::select! {
            biased;
            event = events.next() => {
                match event {
                    Some(Ok(Event::Mouse(m))) => {
                        // The list pane is the left `LIST_PCT`% (matching the
                        // layout split); the rest is the output pane. The wheel
                        // acts on whichever the cursor is over.
                        let list_width = terminal.size()?.width * LIST_PCT / 100;
                        let over_list = m.column < list_width;
                        let shift = m.modifiers.contains(KeyModifiers::SHIFT);
                        match m.kind {
                            // Over the host list the wheel switches hosts.
                            MouseEventKind::ScrollUp if over_list => {
                                selected = selected.saturating_sub(1);
                                scroll = OutputScroll::default();
                            }
                            MouseEventKind::ScrollDown if over_list => {
                                selected = (selected + 1).min(hosts.len().saturating_sub(1));
                                scroll = OutputScroll::default();
                            }
                            // Over the output: plain wheel scrolls vertically,
                            // Shift+wheel scrolls horizontally. Terminals that
                            // emit a native horizontal wheel (ScrollLeft/Right)
                            // are handled below too.
                            MouseEventKind::ScrollUp if shift => {
                                scroll.horiz = scroll.horiz.saturating_sub(6)
                            }
                            MouseEventKind::ScrollDown if shift => {
                                scroll.horiz = scroll.horiz.saturating_add(6)
                            }
                            MouseEventKind::ScrollUp => scroll.vert = scroll.vert.saturating_add(3),
                            MouseEventKind::ScrollDown => {
                                scroll.vert = scroll.vert.saturating_sub(3)
                            }
                            MouseEventKind::ScrollLeft => {
                                scroll.horiz = scroll.horiz.saturating_sub(6)
                            }
                            MouseEventKind::ScrollRight => {
                                scroll.horiz = scroll.horiz.saturating_add(6)
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        // Ctrl-C aborts the play immediately, no
                        // confirmation — raw mode swallows the signal, and
                        // nothing reads as "stuck" quite like a TUI that
                        // ignores Ctrl-C. The `abort` flip is what actually
                        // stops the deployments (see `main`).
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && key.code == KeyCode::Char('c')
                        {
                            let _ = abort.send(true);
                            return Ok(());
                        }
                        if confirm_quit {
                            match key.code {
                                KeyCode::Char('y') => {
                                    let _ = abort.send(true);
                                    return Ok(());
                                }
                                _ => confirm_quit = false,
                            }
                            continue;
                        }
                        match key.code {
                            KeyCode::Char('q') => confirm_quit = true,
                            // Jump to the next failed host (wrapping), so a
                            // red ✗ in a long list is one keypress away.
                            KeyCode::Char('f') => {
                                if let Some(next) = hosts
                                    .iter()
                                    .enumerate()
                                    .cycle()
                                    .skip(selected + 1)
                                    .take(hosts.len())
                                    .find(|(_, h)| h.status == Status::Failed)
                                    .map(|(i, _)| i)
                                {
                                    selected = next;
                                    scroll = OutputScroll::default();
                                }
                            }
                            // Switch hosts with Tab / Shift+Tab. The vertical
                            // keys now scroll the output (the thing you read),
                            // not the host list.
                            KeyCode::Tab => {
                                selected = (selected + 1).min(hosts.len().saturating_sub(1));
                                scroll = OutputScroll::default();
                            }
                            KeyCode::BackTab => {
                                selected = selected.saturating_sub(1);
                                scroll = OutputScroll::default();
                            }
                            // Scroll the output vertically. `vert` counts lines
                            // above the live tail, so up adds, down subtracts.
                            KeyCode::Up | KeyCode::Char('k') => {
                                scroll.vert = scroll.vert.saturating_add(1)
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                scroll.vert = scroll.vert.saturating_sub(1)
                            }
                            KeyCode::PageUp => scroll.vert = scroll.vert.saturating_add(10),
                            KeyCode::PageDown => scroll.vert = scroll.vert.saturating_sub(10),
                            // Scroll the output horizontally for long lines
                            // (wide diffs etc.). `draw_output` clamps `horiz`.
                            KeyCode::Left | KeyCode::Char('h') => {
                                scroll.horiz = scroll.horiz.saturating_sub(8)
                            }
                            KeyCode::Right | KeyCode::Char('l') => {
                                scroll.horiz = scroll.horiz.saturating_add(8)
                            }
                            KeyCode::Home => {
                                scroll.vert = u16::MAX;
                                scroll.horiz = 0;
                            }
                            KeyCode::End => scroll.vert = 0,
                            // Resize the bottom log pane. `0` collapses it.
                            KeyCode::Char('+') | KeyCode::Char('=') => {
                                log_height = (log_height + 1).min(40)
                            }
                            KeyCode::Char('-') => log_height = log_height.saturating_sub(1),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            msg = rx.recv(), if channel_open => {
                match msg {
                    Some(Msg::AddHost { name, tags }) => add_host(hosts, name, tags),
                    Some(Msg::Line(idx, src, line)) => {
                        hosts[idx].push_line(src, line);
                        // When scrolled back into history (vert > 0), pin the
                        // view to the same absolute lines as new output arrives
                        // — only the tail (vert == 0) follows new output.
                        if idx == selected && scroll.vert > 0 {
                            scroll.vert = scroll.vert.saturating_add(1);
                        }
                    }
                    Some(Msg::Status(idx, status)) => hosts[idx].set_status(status),
                    Some(Msg::Shutdown) => return Ok(()),
                    None => channel_open = false,
                }
            }
            _ = tick.tick() => {
                frame = frame.wrapping_add(1);
            }
        }
    }
}

/// Per-frame view state handed from the event loop to the renderers.
struct View<'a> {
    selected: usize,
    confirm_quit: bool,
    log_height: u16,
    spinner: &'a str,
}

fn draw(
    f: &mut ratatui::Frame,
    hosts: &[Host],
    list_state: &mut ListState,
    scroll: &mut OutputScroll,
    view: &View<'_>,
) {
    let View {
        selected,
        confirm_quit: _,
        log_height,
        spinner,
    } = *view;
    // Bottom-up: a single-row key legend at the very bottom, the CLI log
    // strip above it, and the rest split into the host list + output panes.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(log_height),
            Constraint::Length(1),
        ])
        .split(f.area());

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(LIST_PCT),
            Constraint::Percentage(100 - LIST_PCT),
        ])
        .split(rows[0]);

    let counts = Counts::of(hosts);
    draw_list(f, panes[0], hosts, list_state, view, &counts);
    draw_output(f, panes[1], hosts.get(selected), scroll, spinner);
    if log_height > 0 {
        draw_log(f, rows[1]);
    }
    draw_legend(f, rows[2], hosts, &counts);
}

/// Single full-width row at the very bottom: key hints while the play is
/// running, replaced by a bold result banner once every host is terminal —
/// so the post-run view states *why* it's still on screen instead of
/// looking hung.
fn draw_legend(f: &mut ratatui::Frame, area: Rect, hosts: &[Host], counts: &Counts) {
    let plural = if hosts.len() == 1 { "host" } else { "hosts" };
    let legend = if !hosts.is_empty() && counts.running == 0 {
        if counts.failed > 0 {
            Line::from(Span::styled(
                format!(
                    " ✗ {} of {} {plural} failed · f: next failed · q: quit",
                    counts.failed,
                    hosts.len()
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ))
        } else {
            Line::from(Span::styled(
                format!(" ✓ all {} {plural} finished · q: quit", hosts.len()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))
        }
    } else {
        // `q: abort` leads so it survives clipping on narrow terminals:
        // while hosts are running, quitting aborts them.
        Line::from(Span::styled(
            " q: abort · Tab: host · f: failed · j/k scroll · h/l pan · PgUp/Dn · Home/End · +/- log",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(Paragraph::new(legend), area);
}

/// Parse a line that may contain ANSI escape codes into a styled ratatui
/// line, falling back to plain text if it doesn't parse.
fn ansi_line(s: &str) -> Line<'static> {
    use ansi_to_tui::IntoText as _;
    s.into_text()
        .ok()
        .and_then(|t| t.lines.into_iter().next())
        .unwrap_or_else(|| Line::raw(s.to_owned()))
}

/// Render a captured line with a fixed-width, colour-coded source prefix,
/// preserving the line's own ANSI styling. The prefix is the same width for
/// both sources so the content columns stay aligned.
fn source_line(src: Source, s: &str) -> Line<'static> {
    let (glyph, color) = match src {
        Source::Orchestrator => ("◆ ", Color::Magenta),
        Source::Worker => ("● ", Color::Cyan),
    };
    let mut line = ansi_line(s);
    line.spans
        .insert(0, Span::styled(glyph, Style::default().fg(color)));
    line
}

fn draw_log(f: &mut ratatui::Frame, area: Rect) {
    let buf = log_buffer()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let view = area.height.saturating_sub(2);
    let start = buf.lines.len().saturating_sub(view as usize);
    let body: Vec<Line> = buf.lines[start..].iter().map(|l| ansi_line(l)).collect();
    let title = if buf.dropped > 0 {
        format!(" cli log · {} lines dropped ", buf.dropped)
    } else {
        " cli log ".to_owned()
    };
    let para = Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(para, area);
}

fn draw_list(
    f: &mut ratatui::Frame,
    area: Rect,
    hosts: &[Host],
    list_state: &mut ListState,
    view: &View<'_>,
    counts: &Counts,
) {
    let View {
        confirm_quit,
        spinner,
        ..
    } = *view;
    // Before discovery has produced any hosts, say what's happening
    // instead of presenting an empty black pane.
    if hosts.is_empty() {
        let placeholder = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(
                format!(" {spinner} waiting for hosts…"),
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                "   compiling & discovering targets",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "   (progress in the cli log below)",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" hosts "));
        f.render_widget(placeholder, area);
        draw_confirm_quit(f, area, confirm_quit);
        return;
    }

    let items: Vec<ListItem> = hosts
        .iter()
        .map(|h| {
            let glyph = match h.status {
                Status::Running => spinner,
                s => s.glyph(),
            };
            let mut spans = vec![
                Span::styled(format!("{glyph} "), Style::default().fg(h.status.color())),
                Span::raw(h.name.clone()),
                Span::styled(
                    format!("  {}", fmt_duration(h.runtime())),
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            if !h.tags.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", h.tags.join(",")),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = if counts.running > 0 {
        format!(
            " {spinner} {} running · {} ok · {} failed ",
            counts.running, counts.done, counts.failed
        )
    } else {
        format!(" {} ok · {} failed ", counts.done, counts.failed)
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, area, list_state);

    draw_confirm_quit(f, area, confirm_quit);
}

/// Red `abort? y/n` prompt overlaid on the bottom edge of the list pane.
fn draw_confirm_quit(f: &mut ratatui::Frame, area: Rect, confirm_quit: bool) {
    if !confirm_quit {
        return;
    }
    let hint =
        Paragraph::new("abort play? y/n (Esc cancels)").style(Style::default().fg(Color::Red));
    let bar = Rect {
        x: area.x + 1,
        y: area.y + area.height.saturating_sub(1),
        width: area.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(hint, bar);
}

fn draw_output(
    f: &mut ratatui::Frame,
    area: Rect,
    host: Option<&Host>,
    scroll: &mut OutputScroll,
    spinner: &str,
) {
    let body: Vec<Line> = match host {
        Some(h) => h
            .lines
            .iter()
            .map(|(src, l)| source_line(*src, l))
            .collect(),
        None => Vec::new(),
    };
    let total = body.len() as u16;
    // Visible rows/cols inside the bordered block.
    let view = area.height.saturating_sub(2);
    let view_w = area.width.saturating_sub(2);
    // `max_top` shows the tail (last line at the bottom). `scroll` is how many
    // lines above the tail we've moved; clamp it here, where the pane's real
    // height is known, so it can never run past the oldest line.
    let max_top = total.saturating_sub(view);
    scroll.vert = scroll.vert.min(max_top);
    let top = max_top - scroll.vert;
    // Lines aren't wrapped, so clamp the horizontal pan to the widest line
    // (minus the visible width) — panning further would only reveal blank
    // space. Done here because the pane's real width is known.
    let widest = body.iter().map(|l| l.width() as u16).max().unwrap_or(0);
    let max_left = widest.saturating_sub(view_w);
    scroll.horiz = scroll.horiz.min(max_left);

    // Title: the selected host's live status glyph (in its status colour),
    // the line count (so you can see output still growing even while
    // scrolled back), and a marker when not following the tail.
    let title = match host {
        Some(h) => {
            let glyph = match h.status {
                Status::Running => spinner,
                s => s.glyph(),
            };
            let mut spans = vec![
                Span::raw(" "),
                Span::styled(format!("{glyph} "), Style::default().fg(h.status.color())),
                Span::raw(format!("{} · {} lines", h.name, h.dropped + h.lines.len())),
            ];
            if scroll.vert > 0 {
                spans.push(Span::styled(
                    format!(" · ↑{}", scroll.vert),
                    Style::default().fg(Color::Yellow),
                ));
            }
            spans.push(Span::raw(" "));
            Line::from(spans)
        }
        None => Line::raw(" output "),
    };

    let para = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title(title))
        .scroll((top, scroll.horiz));
    f.render_widget(para, area);

    // A scrollbar whenever there's more output than fits, so "there is
    // history above" is visible without memorising the ↑ marker.
    if total > view {
        let mut state = ScrollbarState::new(max_top as usize).position(top as usize);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut state,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    /// The CLI's own log pane gets the same cap as the host panes: a
    /// long play's `tracing` output must not grow it without bound, and
    /// the title must stay truthful about what was evicted.
    #[test]
    fn cli_log_buffer_is_capped_and_counts_dropped() {
        use std::io::Write as _;

        let mut writer = LogWriter;
        for i in 0..(MAX_LINES + 500) {
            // One write call per line, the way the tracing subscriber
            // delivers a formatted event.
            writer.write_all(format!("line {i}\n").as_bytes()).unwrap();
        }
        let buf = log_buffer()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(buf.lines.len(), MAX_LINES);
        assert!(buf.dropped >= 500);
        // The newest content survived; the oldest was evicted.
        assert_eq!(
            buf.lines.last().unwrap(),
            &format!("line {}", MAX_LINES + 499)
        );
        assert!(buf.lines[0].starts_with("line "));
    }

    fn host(name: &str, status: Status) -> Host {
        let mut h = Host {
            name: name.into(),
            tags: vec!["env:test".into()],
            status: Status::Running,
            lines: vec![(Source::Worker, "hello".into())],
            dropped: 0,
            started: std::time::Instant::now(),
            elapsed: None,
        };
        h.set_status(status);
        h
    }

    /// Render one frame at 100×30 and return the screen as text lines.
    fn render(hosts: &[Host]) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut list_state = ListState::default();
        let mut scroll = OutputScroll::default();
        let view = View {
            selected: 0,
            confirm_quit: false,
            log_height: 6,
            spinner: SPINNER[0],
        };
        terminal
            .draw(|f| draw(f, hosts, &mut list_state, &mut scroll, &view))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn placeholder_before_discovery() {
        let screen = render(&[]);
        assert!(screen.contains("waiting for hosts…"), "{screen}");
        assert!(screen.contains("compiling & discovering"), "{screen}");
        // Key hints, not a result banner, while nothing is terminal.
        // `q: abort` leads the hint line so it can't be clipped away.
        assert!(screen.contains("q: abort"), "{screen}");
    }

    #[test]
    fn running_host_shows_spinner_and_runtime() {
        let hosts = vec![host("ap-01", Status::Running)];
        let screen = render(&hosts);
        assert!(screen.contains(SPINNER[0]), "{screen}");
        assert!(screen.contains("ap-01"), "{screen}");
        assert!(screen.contains("0.0s"), "{screen}");
        assert!(screen.contains("1 running"), "{screen}");
    }

    #[test]
    fn all_finished_shows_green_banner() {
        let hosts = vec![host("a", Status::Finished), host("b", Status::Finished)];
        let screen = render(&hosts);
        assert!(
            screen.contains("✓ all 2 hosts finished · q: quit"),
            "{screen}"
        );
    }

    #[test]
    fn failures_show_red_banner_with_count() {
        let hosts = vec![host("a", Status::Finished), host("b", Status::Failed)];
        let screen = render(&hosts);
        assert!(screen.contains("✗ 1 of 2 hosts failed"), "{screen}");
        // The failed host's glyph is in the list, and the output-pane
        // title carries the selected host's glyph too.
        assert!(screen.contains("✗ b"), "{screen}");
    }

    #[test]
    fn output_title_has_line_count_and_status() {
        let hosts = vec![host("web-01", Status::Finished)];
        let screen = render(&hosts);
        assert!(screen.contains("✓ web-01 · 1 lines"), "{screen}");
    }

    #[test]
    fn output_history_is_capped_but_count_stays_truthful() {
        let mut h = host("chatty", Status::Running);
        h.lines.clear();
        for i in 0..(MAX_LINES + 500) {
            h.push_line(Source::Worker, format!("line {i}"));
        }
        assert_eq!(h.lines.len(), MAX_LINES);
        assert_eq!(h.dropped, 500);
        assert_eq!(h.lines[0].1, "line 500");
        let screen = render(&[h]);
        assert!(
            screen.contains(&format!("chatty · {} lines", MAX_LINES + 500)),
            "{screen}"
        );
    }

    #[test]
    fn strip_ansi_removes_escape_codes() {
        assert_eq!(strip_ansi("\x1b[31mfailed\x1b[0m"), "failed");
        assert_eq!(strip_ansi("plain"), "plain");
    }
}
