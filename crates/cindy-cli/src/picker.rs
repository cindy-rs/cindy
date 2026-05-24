//! Telescope-style interactive picker: fuzzy-filterable multi-select
//! list on the left, file preview (centered on the item's line) on the
//! right.
//!
//! Used by `cindy secret seal` / `unseal` to choose which secrets to
//! process. Runs on stderr so stdout stays clean; only invoked when
//! stderr is a TTY (callers check; see [`stderr_is_tty`]).
//!
//! Key bindings (fzf-flavoured — Space stays typeable for multi-atom
//! fuzzy queries):
//!
//!   * type           — fuzzy-filter the list ([`nucleo_matcher`])
//!   * Up/Down, Ctrl-P/Ctrl-N — move cursor
//!   * Space          — toggle mark on the current item (cursor stays)
//!   * Tab / Shift-Tab — toggle mark, then move down / up
//!   * Ctrl-A         — toggle all currently *visible* (filtered) items
//!
//! Because Space toggles, it cannot be typed into the filter query;
//! queries are single fuzzy atoms.
//!   * Enter          — confirm: return every marked item
//!   * Esc / Ctrl-C   — cancel the whole command
//!
//! All items start **unmarked**; mark what you want with Space/Tab
//! (or Ctrl-A for everything visible), then confirm with Enter.

use std::collections::HashMap;
use std::io::IsTerminal as _;
use std::path::PathBuf;

use eyre::WrapErr as _;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32String};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::crossterm::{event, execute};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

/// One selectable row.
pub struct PickItem {
    /// Rendered in the list pane.
    pub label: String,
    /// File shown in the preview pane.
    pub path: PathBuf,
    /// 1-based line the preview centres on and highlights.
    pub line: u32,
}

/// True iff stderr is attached to a terminal (the picker draws there).
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Run the picker. Returns the indices (into `items`, original order)
/// of the marked items on Enter, or `None` if the user cancelled.
pub fn pick(title: &str, items: &[PickItem]) -> eyre::Result<Option<Vec<usize>>> {
    if items.is_empty() {
        return Ok(Some(Vec::new()));
    }

    enable_raw_mode().context("enabling raw terminal mode for the picker")?;
    execute!(std::io::stderr(), EnterAlternateScreen)
        .context("entering alternate screen for the picker")?;

    let result = run(title, items);

    // Always restore the terminal, even when `run` errored.
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stderr(), LeaveAlternateScreen);

    result
}

struct State<'a> {
    items: &'a [PickItem],
    /// Haystacks pre-converted for nucleo.
    haystacks: Vec<Utf32String>,
    matcher: Matcher,
    query: String,
    /// Indices into `items`, filtered + ranked by the current query.
    filtered: Vec<usize>,
    /// Cursor position within `filtered`.
    cursor: usize,
    /// Mark state per original item index.
    marked: Vec<bool>,
    /// Lazily loaded preview lines per file.
    previews: HashMap<PathBuf, Vec<String>>,
}

impl<'a> State<'a> {
    fn new(items: &'a [PickItem]) -> Self {
        let haystacks = items
            .iter()
            .map(|i| Utf32String::from(i.label.as_str()))
            .collect();
        let mut s = Self {
            items,
            haystacks,
            matcher: Matcher::new(Config::DEFAULT),
            query: String::new(),
            filtered: (0..items.len()).collect(),
            cursor: 0,
            marked: vec![false; items.len()],
            previews: HashMap::new(),
        };
        s.refilter();
        s
    }

    fn refilter(&mut self) {
        if self.query.is_empty() {
            self.filtered = (0..self.items.len()).collect();
        } else {
            let pattern = Pattern::parse(&self.query, CaseMatching::Ignore, Normalization::Smart);
            let mut scored: Vec<(u32, usize)> = self
                .haystacks
                .iter()
                .enumerate()
                .filter_map(|(i, hay)| {
                    pattern
                        .score(hay.slice(..), &mut self.matcher)
                        .map(|score| (score, i))
                })
                .collect();
            // Highest score first; stable on index for determinism.
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            self.filtered = scored.into_iter().map(|(_, i)| i).collect();
        }
        self.cursor = self.cursor.min(self.filtered.len().saturating_sub(1));
    }

    fn current(&self) -> Option<usize> {
        self.filtered.get(self.cursor).copied()
    }

    fn preview_lines(&mut self, idx: usize) -> &[String] {
        let path = &self.items[idx].path;
        self.previews
            .entry(path.clone())
            .or_insert_with(|| match std::fs::read_to_string(path) {
                Ok(content) => content.lines().map(str::to_owned).collect(),
                Err(e) => vec![format!("<couldn't read {}: {e}>", path.display())],
            })
    }
}

fn run(title: &str, items: &[PickItem]) -> eyre::Result<Option<Vec<usize>>> {
    let backend = CrosstermBackend::new(std::io::stderr());
    let mut terminal = Terminal::new(backend).context("initialising the picker terminal")?;
    let mut state = State::new(items);

    loop {
        terminal
            .draw(|f| draw(f, title, &mut state))
            .context("drawing the picker")?;

        // Block on the next input event; redraw on resize.
        match event::read().context("reading terminal input")? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('c') if ctrl => return Ok(None),
                    KeyCode::Enter => {
                        return Ok(Some(
                            (0..items.len()).filter(|&i| state.marked[i]).collect(),
                        ));
                    }
                    KeyCode::Up => move_cursor(&mut state, -1),
                    KeyCode::Down => move_cursor(&mut state, 1),
                    KeyCode::Char('p') if ctrl => move_cursor(&mut state, -1),
                    KeyCode::Char('n') if ctrl => move_cursor(&mut state, 1),
                    KeyCode::Char('a') if ctrl => {
                        // Toggle all *visible* items: if any visible is
                        // unmarked, mark all; else unmark all.
                        let any_unmarked = state.filtered.iter().any(|&i| !state.marked[i]);
                        for &i in &state.filtered {
                            state.marked[i] = any_unmarked;
                        }
                    }
                    KeyCode::Char(' ') if !ctrl => {
                        if let Some(i) = state.current() {
                            state.marked[i] = !state.marked[i];
                        }
                    }
                    KeyCode::Tab => {
                        if let Some(i) = state.current() {
                            state.marked[i] = !state.marked[i];
                        }
                        move_cursor(&mut state, 1);
                    }
                    KeyCode::BackTab => {
                        if let Some(i) = state.current() {
                            state.marked[i] = !state.marked[i];
                        }
                        move_cursor(&mut state, -1);
                    }
                    KeyCode::Backspace => {
                        state.query.pop();
                        state.refilter();
                    }
                    KeyCode::Char('u') if ctrl => {
                        state.query.clear();
                        state.refilter();
                    }
                    KeyCode::Char(c) if !ctrl => {
                        state.query.push(c);
                        state.refilter();
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn move_cursor(state: &mut State, delta: i64) {
    if state.filtered.is_empty() {
        return;
    }
    let len = state.filtered.len() as i64;
    let next = (state.cursor as i64 + delta).clamp(0, len - 1);
    state.cursor = next as usize;
}

fn draw(f: &mut ratatui::Frame, title: &str, state: &mut State) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(f.area());

    draw_list(f, panes[0], title, state);
    draw_preview(f, panes[1], state);
}

fn draw_list(f: &mut ratatui::Frame, area: Rect, title: &str, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // list
            Constraint::Length(3), // query input
        ])
        .split(area);

    let marked_count = state.marked.iter().filter(|&&m| m).count();
    let rows: Vec<ListItem> = state
        .filtered
        .iter()
        .map(|&i| {
            let mark = if state.marked[i] { "[x] " } else { "[ ] " };
            let mark_style = if state.marked[i] {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(vec![
                Span::styled(mark, mark_style),
                Span::raw(state.items[i].label.clone()),
            ]))
        })
        .collect();

    let list = List::new(rows)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {title} ({marked_count}/{} marked) ",
            state.items.len()
        )))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::BOLD),
        );

    let mut list_state = ListState::default();
    if !state.filtered.is_empty() {
        list_state.select(Some(state.cursor));
    }
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Cyan)),
        Span::raw(state.query.as_str()),
        Span::styled("█", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).title(
        " type: filter · space: toggle · tab: toggle+move · ctrl-a: all · enter: go · esc: cancel ",
    ));
    f.render_widget(input, chunks[1]);
}

fn draw_preview(f: &mut ratatui::Frame, area: Rect, state: &mut State) {
    let Some(idx) = state.current() else {
        let empty = Paragraph::new("nothing matches the filter")
            .block(Block::default().borders(Borders::ALL).title(" preview "));
        f.render_widget(empty, area);
        return;
    };

    let target_line = state.items[idx].line as usize; // 1-based
    let title = format!(
        " {}:{} ",
        state.items[idx].path.display(),
        state.items[idx].line
    );
    let lines = state.preview_lines(idx);

    // Window centred on the target line.
    let inner_height = area.height.saturating_sub(2) as usize; // borders
    let half = inner_height / 2;
    let first = target_line.saturating_sub(half + 1); // 0-based index of first shown line
    let gutter_width = (first + inner_height).max(1).to_string().len();

    let rendered: Vec<Line> = lines
        .iter()
        .enumerate()
        .skip(first)
        .take(inner_height)
        .map(|(i, text)| {
            let lineno = i + 1;
            let gutter = format!("{lineno:>gutter_width$} │ ");
            if lineno == target_line {
                Line::from(vec![
                    Span::styled(gutter, Style::default().fg(Color::Yellow)),
                    Span::styled(
                        text.clone(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(gutter, Style::default().fg(Color::DarkGray)),
                    Span::raw(text.clone()),
                ])
            }
        })
        .collect();

    let preview =
        Paragraph::new(rendered).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(preview, area);
}
