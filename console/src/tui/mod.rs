//! Terminal dashboard. Reads only the snapshot file; draws only sanitised strings.

mod globe;
mod theme;

use crate::snapshot::{Category, Group, Snapshot, Tuning, hour_of, short_time};
use crate::source::{Freshness, POLL_INTERVAL, SnapshotSource};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Tabs,
    Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use std::time::{Duration, Instant};
use theme::*;

const APP_TITLE: &str = " SOC THIEF // NIGHT SHIFT ";
const FILTER_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Groups,
    Health,
    History,
    Globe,
}

impl View {
    const ALL: [View; 5] = [
        View::Overview,
        View::Groups,
        View::Health,
        View::History,
        View::Globe,
    ];

    fn index(self) -> usize {
        Self::ALL.iter().position(|v| *v == self).unwrap_or(0)
    }

    fn title(self) -> &'static str {
        match self {
            View::Overview => "1 OVERVIEW",
            View::Groups => "2 GROUPS",
            View::Health => "3 HEALTH",
            View::History => "4 HISTORY",
            View::Globe => "5 GLOBE",
        }
    }
}

pub struct App {
    pub source: SnapshotSource,
    pub view: View,
    pub detail: bool,
    pub filter: String,
    pub editing_filter: bool,
    pub category: Option<Category>,
    pub quit: bool,
    groups_state: TableState,
    health_state: TableState,
    history_state: TableState,
    globe: Option<globe::Globe>,
    globe_generation: u64,
    started: Instant,
}

impl App {
    pub fn new(source: SnapshotSource) -> Self {
        App {
            source,
            view: View::Overview,
            detail: false,
            filter: String::new(),
            editing_filter: false,
            category: None,
            quit: false,
            groups_state: TableState::default().with_selected(0),
            health_state: TableState::default().with_selected(0),
            history_state: TableState::default().with_selected(0),
            globe: None,
            globe_generation: 0,
            started: Instant::now(),
        }
    }

    fn snapshot(&self) -> Option<&Snapshot> {
        self.source.snapshot().map(|s| s.as_ref())
    }

    /// Indices into `snapshot.groups` that pass the current filters, in digest order.
    pub fn visible_groups(&self) -> Vec<usize> {
        let Some(snap) = self.snapshot() else {
            return Vec::new();
        };
        let needle = self.filter.to_lowercase();
        snap.groups
            .iter()
            .enumerate()
            .filter(|(_, g)| self.category.is_none_or(|c| g.category == c))
            .filter(|(_, g)| needle.is_empty() || group_matches(g, &needle))
            .map(|(i, _)| i)
            .collect()
    }

    fn selected_group(&self) -> Option<&Group> {
        let idx = *self
            .visible_groups()
            .get(self.groups_state.selected().unwrap_or(0))?;
        self.snapshot()?.groups.get(idx)
    }

    fn row_count(&self) -> usize {
        let Some(snap) = self.snapshot() else {
            return 0;
        };
        match self.view {
            View::Overview | View::Globe => 0,
            View::Groups => self.visible_groups().len(),
            View::Health => snap.health.checks.len(),
            View::History => snap.history.len(),
        }
    }

    fn state_mut(&mut self) -> Option<&mut TableState> {
        match self.view {
            View::Overview | View::Globe => None,
            View::Groups => Some(&mut self.groups_state),
            View::Health => Some(&mut self.health_state),
            View::History => Some(&mut self.history_state),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let n = self.row_count();
        if let Some(state) = self.state_mut() {
            let cur = state.selected().unwrap_or(0) as isize;
            let max = n.saturating_sub(1) as isize;
            state.select(Some((cur + delta).clamp(0, max) as usize));
        }
    }

    /// Keep selections inside their lists after a reload or a filter change.
    fn clamp_selections(&mut self) {
        let (g, h, hi) = match self.snapshot() {
            Some(s) => (
                self.visible_groups().len(),
                s.health.checks.len(),
                s.history.len(),
            ),
            None => (0, 0, 0),
        };
        for (state, n) in [
            (&mut self.groups_state, g),
            (&mut self.health_state, h),
            (&mut self.history_state, hi),
        ] {
            let cur = state.selected().unwrap_or(0);
            state.select(Some(cur.min(n.saturating_sub(1))));
        }
        if g == 0 {
            self.detail = false;
        }
    }

    pub fn poll(&mut self) {
        if self.source.poll() {
            self.clamp_selections();
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.editing_filter {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.editing_filter = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) if !c.is_control() && self.filter.chars().count() < FILTER_MAX => {
                    self.filter.push(c);
                }
                _ => {}
            }
            self.groups_state.select(Some(0));
            self.clamp_selections();
            return;
        }
        if self.view == View::Globe
            && let Some(g) = self.globe.as_mut()
        {
            match key.code {
                KeyCode::Char(' ') => return g.paused = !g.paused,
                KeyCode::Char('+') | KeyCode::Char('=') => return g.faster(),
                KeyCode::Char('-') => return g.slower(),
                KeyCode::Char('m') => return g.show_tuned = !g.show_tuned,
                KeyCode::Char('l') => return g.locked = !g.locked,
                _ => {}
            }
        }
        let views = View::ALL.len();
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Tab => self.set_view(View::ALL[(self.view.index() + 1) % views]),
            KeyCode::BackTab => self.set_view(View::ALL[(self.view.index() + views - 1) % views]),
            KeyCode::Char(c @ '1'..='5') => {
                self.set_view(View::ALL[(c as u8 - b'1') as usize]);
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX / 2),
            KeyCode::Enter => {
                if self.view == View::Groups && self.selected_group().is_some() {
                    self.detail = true;
                }
            }
            KeyCode::Esc => {
                if self.detail {
                    self.detail = false;
                } else if !self.filter.is_empty() || self.category.is_some() {
                    self.filter.clear();
                    self.category = None;
                    self.clamp_selections();
                }
            }
            KeyCode::Char('/') => {
                self.set_view(View::Groups);
                self.detail = false;
                self.editing_filter = true;
            }
            KeyCode::Char('c') => {
                self.category = match self.category {
                    None => Some(Category::ALL[0]),
                    Some(c) => Category::ALL
                        .iter()
                        .position(|x| *x == c)
                        .and_then(|i| Category::ALL.get(i + 1).copied()),
                };
                self.set_view(View::Groups);
                self.detail = false;
                self.groups_state.select(Some(0));
                self.clamp_selections();
            }
            KeyCode::Char('r') => {
                self.source.reload();
                self.clamp_selections();
            }
            _ => {}
        }
    }

    fn set_view(&mut self, view: View) {
        if view != self.view {
            self.detail = false;
        }
        self.view = view;
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Block::new().style(base()), area);
        let [header, tabs, body, footer] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        self.render_header(frame, header);
        let tab_titles = View::ALL.map(View::title);
        frame.render_widget(
            Tabs::new(tab_titles)
                .select(self.view.index())
                .style(Style::new().fg(DIM))
                .highlight_style(badge())
                .divider(Span::styled(" ", border())),
            tabs,
        );

        if self.snapshot().is_none() {
            self.render_unavailable(frame, body);
        } else {
            match self.view {
                View::Overview => self.render_overview(frame, body),
                View::Groups if self.detail => self.render_detail(frame, body),
                View::Groups => self.render_groups(frame, body),
                View::Health => self.render_health(frame, body),
                View::History => self.render_history(frame, body),
                View::Globe => self.render_globe(frame, body),
            }
        }
        self.render_footer(frame, footer);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .border_type(BorderType::Thick)
            .border_style(Style::new().fg(AMBER))
            .title(Span::styled(APP_TITLE, title()))
            .padding(ratatui::widgets::Padding::horizontal(1))
            .style(panel());
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut top = Vec::new();
        let mut bottom = Vec::new();
        if let Some(s) = self.snapshot() {
            if s.is_demo() {
                top.push(Span::styled(" DEMO DATA ", badge()));
                top.push(Span::raw(" "));
            }
            top.push(Span::styled("WINDOW ", label()));
            top.push(Span::styled(
                format!(
                    "{} → {}",
                    short_time(&s.window.start),
                    short_time(&s.window.end)
                ),
                Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
            ));
            if !s.timezone.is_empty() {
                top.push(Span::styled(
                    format!("  {}", s.timezone),
                    Style::new().fg(DIM),
                ));
            }
            top.push(Span::styled("   HEALTH ", label()));
            top.push(Span::styled(
                s.health.status.label(),
                status(&s.health.status),
            ));
            let paged = s.breaches.iter().filter(|b| b.paged).count();
            if paged > 0 {
                top.push(Span::raw("   "));
                top.push(Span::styled(format!(" {paged} PAGED BREACH "), alarm()));
            }
            bottom.push(Span::styled("GENERATED ", label()));
            bottom.push(Span::styled(
                short_time(&s.generated_at),
                Style::new().fg(TEXT),
            ));
        }
        bottom.push(Span::raw("   "));
        match self.source.freshness() {
            Freshness::Live => bottom.push(Span::styled("● LIVE", Style::new().fg(GREEN))),
            Freshness::Stale => {
                bottom.push(Span::styled(" STALE ", alarm()));
                if let Some(e) = self.source.error() {
                    bottom.push(Span::styled(
                        format!(" reload failed: {e}"),
                        Style::new().fg(RED),
                    ));
                }
            }
            Freshness::Unavailable => {
                bottom.push(Span::styled(" NO SNAPSHOT ", alarm()));
            }
        }
        frame.render_widget(
            Paragraph::new(vec![Line::from(top), Line::from(bottom)]),
            inner,
        );
    }

    fn render_unavailable(&self, frame: &mut Frame, area: Rect) {
        let err = self
            .source
            .error()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no snapshot loaded".into());
        let path = crate::snapshot::sanitize(&self.source.path().display().to_string(), 200);
        let text = vec![
            Line::from(Span::styled(
                "NO SNAPSHOT TO SHOW",
                Style::new().fg(RED).bold(),
            )),
            Line::default(),
            Line::from(vec![Span::styled("FILE   ", label()), Span::raw(path)]),
            Line::from(vec![Span::styled("ERROR  ", label()), Span::raw(err)]),
            Line::default(),
            Line::from(Span::styled(
                "Waiting for the file. It is re-read every 2 seconds; press r to retry now.",
                Style::new().fg(DIM),
            )),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .block(panel_block(" ERROR ").border_style(Style::new().fg(RED))),
            area,
        );
    }

    fn render_overview(&self, frame: &mut Frame, area: Rect) {
        let Some(s) = self.snapshot() else { return };
        let [stats, chart, breaches] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Fill(1),
        ])
        .areas(area);

        let delivered = s
            .groups
            .iter()
            .filter(|g| g.decision.delivery_required)
            .count();
        let tiles: [(&str, String, Style); 6] = [
            ("EVENTS", fmt_num(s.window.events), Style::new().fg(AMBER)),
            ("GROUPS", fmt_num(s.window.groups), Style::new().fg(AMBER)),
            (
                "DUPLICATES",
                fmt_num(s.window.duplicates),
                Style::new().fg(TEXT),
            ),
            (
                "MUTED BY TUNING",
                fmt_num(s.window.muted_by_tuning),
                Style::new().fg(ORANGE),
            ),
            (
                "DELIVERY REQUIRED",
                fmt_num(delivered as u64),
                Style::new().fg(RED),
            ),
            (
                "HEALTH",
                s.health.status.label().to_string(),
                status(&s.health.status),
            ),
        ];
        let cols = Layout::horizontal([Constraint::Ratio(1, 6); 6]).split(stats);
        for ((name, value, style), col) in tiles.into_iter().zip(cols.iter()) {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(value, style.bold())))
                    .block(panel_block(name)),
                *col,
            );
        }

        self.render_timeline(frame, chart, s);

        let mut lines: Vec<Line> = Vec::new();
        if s.breaches.is_empty() {
            lines.push(Line::from(Span::styled(
                "No breach signals in this window.",
                Style::new().fg(GREEN),
            )));
        }
        for b in &s.breaches {
            let mut spans = vec![if b.paged {
                Span::styled(" PAGED ", alarm())
            } else {
                Span::styled(" seen  ", Style::new().fg(ORANGE).bg(PANEL_HI))
            }];
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                b.name.clone(),
                if b.paged {
                    Style::new().fg(RED).bold()
                } else {
                    Style::new().fg(TEXT)
                },
            ));
            spans.push(Span::styled(
                format!("  {}  {}", b.agent, short_time(&b.at)),
                Style::new().fg(DIM),
            ));
            if !b.signals.is_empty() {
                spans.push(Span::styled(
                    format!("  [{}]", b.signals.join(", ")),
                    Style::new().fg(DIM),
                ));
            }
            lines.push(Line::from(spans));
        }
        let border_col = if s.breaches.iter().any(|b| b.paged) {
            RED
        } else {
            BORDER
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(panel_block(" BREACHES ").border_style(Style::new().fg(border_col))),
            breaches,
        );
    }

    fn render_timeline(&self, frame: &mut Frame, area: Rect, s: &Snapshot) {
        let block = panel_block(" EVENTS PER HOUR  ·  DELIVERY-REQUIRED BELOW ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if s.timeline.is_empty() || inner.width < 4 || inner.height < 4 {
            frame.render_widget(
                Paragraph::new(Span::styled("no timeline", Style::new().fg(DIM))),
                inner,
            );
            return;
        }
        let [label_col, plot] =
            Layout::horizontal([Constraint::Length(9), Constraint::Fill(1)]).areas(inner);
        let [ev_area, dr_area, axis] = Layout::vertical([
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(plot);
        let [ev_label, dr_label, _] = Layout::vertical([
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(label_col);

        let n = s.timeline.len();
        let col = (plot.width as usize / n).max(1);
        let widen = |v: Vec<u64>| -> Vec<u64> {
            v.into_iter()
                .flat_map(|x| std::iter::repeat_n(x, col))
                .collect()
        };
        let ev: Vec<u64> = widen(s.timeline.iter().map(|b| b.events).collect());
        let dr: Vec<u64> = widen(s.timeline.iter().map(|b| b.delivery_required).collect());
        let ev_max = s.timeline.iter().map(|b| b.events).max().unwrap_or(0);
        let dr_max = s
            .timeline
            .iter()
            .map(|b| b.delivery_required)
            .max()
            .unwrap_or(0);

        frame.render_widget(
            Sparkline::default().data(ev).style(Style::new().fg(AMBER)),
            ev_area,
        );
        frame.render_widget(
            Sparkline::default().data(dr).style(Style::new().fg(RED)),
            dr_area,
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("events", label())),
                Line::from(Span::styled(fmt_num(ev_max), Style::new().fg(AMBER))),
            ]),
            ev_label,
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("deliver", label())),
                Line::from(Span::styled(fmt_num(dr_max), Style::new().fg(RED))),
            ]),
            dr_label,
        );

        let every = 3usize.div_ceil(col).max(1);
        let mut axis_line = String::new();
        for (i, b) in s.timeline.iter().enumerate() {
            let cell = if i % every == 0 {
                hour_of(&b.start)
            } else {
                String::new()
            };
            let width = col.max(1);
            let mut piece: String = cell.chars().take(width).collect();
            while piece.chars().count() < width {
                piece.push(' ');
            }
            axis_line.push_str(&piece);
        }
        frame.render_widget(
            Paragraph::new(Span::styled(axis_line, Style::new().fg(DIM))),
            axis,
        );
    }

    fn render_groups(&mut self, frame: &mut Frame, area: Rect) {
        let [filter_area, table_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);

        let visible = self.visible_groups();
        let Some(snap) = self.source.snapshot().cloned() else {
            return;
        };

        let mut f = vec![Span::styled(" FILTER ", label())];
        if self.editing_filter {
            f.push(Span::styled(
                format!("{}▏", self.filter),
                Style::new().fg(AMBER).bg(PANEL_HI),
            ));
        } else if self.filter.is_empty() {
            f.push(Span::styled("(none — press /)", Style::new().fg(DIM)));
        } else {
            f.push(Span::styled(self.filter.clone(), Style::new().fg(AMBER)));
        }
        f.push(Span::styled("   CATEGORY ", label()));
        f.push(match self.category {
            Some(c) => Span::styled(c.label(), category(c)),
            None => Span::styled("all — press c", Style::new().fg(DIM)),
        });
        f.push(Span::styled(
            format!("   {} of {} groups", visible.len(), snap.groups.len()),
            Style::new().fg(DIM),
        ));
        if let Some((listed, total)) = snap.groups_capped() {
            f.push(Span::styled(
                format!(
                    "   showing {} of {} groups",
                    fmt_num(listed as u64),
                    fmt_num(total)
                ),
                Style::new().fg(ORANGE).bold(),
            ));
        }
        frame.render_widget(Paragraph::new(Line::from(f)), filter_area);

        let header = Row::new(
            [
                "CATEGORY",
                "LVL",
                "RULE",
                "DESCRIPTION",
                "COUNT",
                "AGENTS",
                "TUNING",
                "DECISION",
            ]
            .map(|h| Cell::from(Span::styled(h, label()))),
        )
        .style(Style::new().bg(PANEL_HI));

        let rows: Vec<Row> = visible
            .iter()
            .filter_map(|&i| snap.groups.get(i))
            .map(|g| {
                let desc = if g.rule_description.is_empty() {
                    Span::styled("(no description in state)", Style::new().fg(DIM))
                } else {
                    Span::raw(g.rule_description.clone())
                };
                let mut tuning_spans = vec![Span::styled(g.tuning.label(), tuning(g.tuning))];
                if g.protected {
                    tuning_spans.push(Span::styled(" PROT", Style::new().fg(GREEN).bold()));
                }
                Row::new(vec![
                    Cell::from(Span::styled(g.category.label(), category(g.category))),
                    Cell::from(Span::styled(g.level.to_string(), level_style(g.level))),
                    Cell::from(g.rule_id.clone()),
                    Cell::from(desc),
                    Cell::from(fmt_num(g.count)),
                    Cell::from(agents_short(g)),
                    Cell::from(Line::from(tuning_spans)),
                    Cell::from(decision_span(g)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(9),
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(9),
            Constraint::Length(9),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(panel_block(" GROUPS · DIGEST ORDER "))
            .row_highlight_style(Style::new().bg(PANEL_HI).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, table_area, &mut self.groups_state);
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let Some(g) = self.selected_group() else {
            return;
        };
        let [top, model_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(8)]).areas(area);

        let kv = |k: &'static str, v: Span<'static>| -> Line<'static> {
            Line::from(vec![Span::styled(format!("{k:<18}"), label()), v])
        };
        let mut lines = vec![
            Line::from(vec![
                Span::styled(format!("RULE {}  ", g.rule_id), title()),
                Span::styled(
                    if g.rule_description.is_empty() {
                        "(no description in state)".to_string()
                    } else {
                        g.rule_description.clone()
                    },
                    Style::new().fg(TEXT).bold(),
                ),
            ]),
            Line::default(),
            kv(
                "CATEGORY",
                Span::styled(g.category.label(), category(g.category)),
            ),
            kv(
                "LEVEL",
                Span::styled(g.level.to_string(), level_style(g.level)),
            ),
            kv("COUNT", Span::raw(fmt_num(g.count))),
            kv(
                "SEEN",
                Span::raw(format!(
                    "{} → {}",
                    short_time(&g.first_seen),
                    short_time(&g.last_seen)
                )),
            ),
            kv(
                "AGENTS",
                Span::raw(if g.agents.is_empty() {
                    "-".to_string()
                } else {
                    g.agents.join(", ")
                }),
            ),
            kv("CASE ID", Span::styled(g.id.clone(), Style::new().fg(DIM))),
            Line::default(),
            kv("DECISION", decision_span(g)),
            kv("REASON", Span::raw(g.decision.reason.clone())),
            kv(
                "HEALTH FAILURE",
                if g.decision.health_failure {
                    Span::styled("YES", Style::new().fg(RED).bold())
                } else {
                    Span::styled("no", Style::new().fg(DIM))
                },
            ),
            kv(
                "PROTECTED",
                if g.protected {
                    Span::styled(
                        "YES — tuning can never hide this group",
                        Style::new().fg(GREEN).bold(),
                    )
                } else {
                    Span::styled("no", Style::new().fg(DIM))
                },
            ),
            kv(
                "TUNING",
                Span::styled(
                    match g.tuning {
                        Tuning::None => "none",
                        Tuning::Low => "low (operator tuning; same as mute at delivery)",
                        Tuning::Mute => "mute (operator tuning)",
                        Tuning::Unknown => "unknown value",
                    },
                    tuning(g.tuning),
                ),
            ),
            kv(
                "BREACH SIGNALS",
                if g.breach_signals.is_empty() {
                    Span::styled("none", Style::new().fg(DIM))
                } else {
                    Span::styled(g.breach_signals.join(", "), Style::new().fg(RED).bold())
                },
            ),
        ];
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Esc back · j/k next group",
            Style::new().fg(DIM),
        )));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(panel_block(" GROUP DETAIL ")),
            top,
        );

        let model_lines = match &g.model {
            None => vec![Line::from(Span::styled(
                "No model ran for this group.",
                Style::new().fg(DIM),
            ))],
            Some(m) => vec![
                kv("MODEL", Span::raw(m.name.clone())),
                kv(
                    "VERDICT",
                    Span::styled(m.verdict.clone(), Style::new().fg(AMBER)),
                ),
                kv(
                    "CONFIDENCE",
                    Span::raw(
                        m.confidence
                            .map(|c| format!("{c:.2}"))
                            .unwrap_or_else(|| "-".into()),
                    ),
                ),
                kv("TAGS", Span::raw(m.tags.join(", "))),
                kv("SUMMARY", Span::raw(m.summary.clone())),
            ],
        };
        frame.render_widget(Clear, model_area);
        frame.render_widget(
            Paragraph::new(model_lines).wrap(Wrap { trim: true }).block(
                panel_block(" MODEL ADVICE · ADVISORY — CANNOT SUPPRESS ")
                    .border_type(BorderType::Plain)
                    .border_style(Style::new().fg(ORANGE)),
            ),
            model_area,
        );
    }

    fn render_health(&mut self, frame: &mut Frame, area: Rect) {
        let Some(s) = self.source.snapshot().cloned() else {
            return;
        };
        let [top, table_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("OVERALL ", label()),
                Span::styled(s.health.status.label(), status(&s.health.status)),
            ]))
            .block(panel_block(" HEALTH ")),
            top,
        );
        let rows: Vec<Row> = s
            .health
            .checks
            .iter()
            .map(|c| {
                Row::new(vec![
                    Cell::from(c.name.clone()),
                    Cell::from(Span::styled(c.status.label(), status(&c.status))),
                    Cell::from(c.detail.clone()),
                ])
            })
            .collect();
        let header = Row::new(["CHECK", "STATUS", "DETAIL"].map(|h| Span::styled(h, label())))
            .style(Style::new().bg(PANEL_HI));
        let table = Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Fill(1),
            ],
        )
        .header(header)
        .block(panel_block(" CHECKS "))
        .row_highlight_style(Style::new().bg(PANEL_HI))
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, table_area, &mut self.health_state);
    }

    fn render_history(&mut self, frame: &mut Frame, area: Rect) {
        let Some(s) = self.source.snapshot().cloned() else {
            return;
        };
        let rows: Vec<Row> = s
            .history
            .iter()
            .map(|h| {
                Row::new(vec![
                    Cell::from(short_time(&h.start)),
                    Cell::from(short_time(&h.end)),
                    Cell::from(fmt_num(h.events)),
                    Cell::from(fmt_num(h.groups)),
                    Cell::from(if h.delivered {
                        Span::styled("yes", Style::new().fg(GREEN))
                    } else {
                        Span::styled("NO", Style::new().fg(RED).bold())
                    }),
                    Cell::from(if h.health_failure {
                        Span::styled("FAILED", Style::new().fg(RED).bold())
                    } else {
                        Span::styled("ok", Style::new().fg(GREEN))
                    }),
                ])
            })
            .collect();
        let header = Row::new(
            ["START", "END", "EVENTS", "GROUPS", "DELIVERED", "HEALTH"]
                .map(|h| Span::styled(h, label())),
        )
        .style(Style::new().bg(PANEL_HI));
        let table = Table::new(
            rows,
            [
                Constraint::Length(17),
                Constraint::Length(17),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .header(header)
        .block(panel_block(" EARLIER WINDOWS · NEWEST FIRST "))
        .row_highlight_style(Style::new().bg(PANEL_HI))
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, area, &mut self.history_state);
    }

    /// The pew pew globe. It replays `attacks` from the snapshot; it changes nothing.
    fn render_globe(&mut self, frame: &mut Frame, area: Rect) {
        let now = self.started.elapsed().as_secs_f64();
        if self.globe.is_none() || self.globe_generation != self.source.generation() {
            // A reloaded file restarts the replay but keeps the viewer's settings.
            let keep = self
                .globe
                .as_ref()
                .map(|g| (g.speed, g.show_tuned, g.locked));
            self.globe = self.snapshot().and_then(|s| s.attacks.as_ref()).map(|a| {
                let mut g = globe::Globe::new(a, 0.0);
                if let Some(k) = keep {
                    (g.speed, g.show_tuned, g.locked) = k;
                }
                g
            });
            self.globe_generation = self.source.generation();
        }
        let block = panel_block("pew pew");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let Some(g) = self.globe.as_mut() else {
            let text = vec![
                Line::from(Span::styled("No attack data in this snapshot.", label())),
                Line::from(Span::styled(
                    "The demo has it. For a real window, run python -m soc_thief.attacks (docs/SNAPSHOT.md).",
                    Style::new().fg(DIM),
                )),
            ];
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), inner);
            return;
        };
        g.advance(now);
        let [main, side] = if inner.width >= 80 {
            Layout::horizontal([Constraint::Fill(1), Constraint::Length(28)]).areas(inner)
        } else {
            [inner, Rect::default()]
        };
        let [map, ticker] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(6)]).areas(main);
        g.draw(map.width as usize, map.height as usize, now)
            .render(map, frame.buffer_mut());

        let ticker_block = panel_block("latest");
        let rows = ticker_block.inner(ticker).height as usize;
        let mut lines = Vec::new();
        if let Some(text) = g.alarm_text(now) {
            lines.push(Line::from(Span::styled(
                format!(" BREACH  {text} "),
                alarm(),
            )));
        }
        let skip = g
            .ticker
            .len()
            .saturating_sub(rows.saturating_sub(lines.len()));
        for shot in g.ticker.iter().skip(skip) {
            let t = shot.t as u64;
            let country = if shot.country.is_empty() {
                "--"
            } else {
                &shot.country
            };
            lines.push(Line::from(Span::styled(
                format!(
                    "+{:02}:{:02}:{:02}  lvl {:>2}  {:<3} {}",
                    t / 3600,
                    t / 60 % 60,
                    t % 60,
                    shot.level,
                    country,
                    shot.label
                ),
                Style::new().fg(globe::Layer::of(shot.kind).colour()),
            )));
        }
        frame.render_widget(Paragraph::new(lines).block(ticker_block), ticker);

        if side.width == 0 {
            return;
        }
        let t = g.clock as u64;
        let mut lines = vec![
            Line::from(vec![
                Span::styled("HOME ", label()),
                Span::styled(
                    if g.has_home() {
                        g.home.clone()
                    } else {
                        "unknown".into()
                    },
                    title(),
                ),
                Span::styled(format!("  ×{}", g.speed), Style::new().fg(TEXT)),
                Span::styled(if g.paused { "  PAUSED" } else { "" }, title()),
            ]),
            Line::from(Span::styled(
                format!("replay +{:02}:{:02}:{:02}", t / 3600, t / 60 % 60, t % 60),
                Style::new().fg(DIM),
            )),
            Line::default(),
            Line::from(Span::styled("LAST HOUR BY SOURCE", label())),
        ];
        let top = g.top_countries(6);
        let most = top.first().map_or(1, |(_, n)| *n).max(1);
        let bar = (side.width as usize).saturating_sub(14).max(1);
        for (code, n) in &top {
            let len = ((*n * bar as u64) / most).max(1) as usize;
            lines.push(Line::from(vec![
                Span::styled(format!("{code:<4}"), Style::new().fg(TEXT)),
                Span::styled(format!("{:<bar$}", "█".repeat(len)), Style::new().fg(AMBER)),
                Span::styled(format!(" {:>6}", fmt_num(*n)), Style::new().fg(DIM)),
            ]));
        }
        lines.push(Line::default());
        let c = &g.counts;
        for (name, n, style) in [
            ("events", c.events, Style::new().fg(TEXT)),
            ("tuned out", c.tuned, Style::new().fg(DIM)),
            ("reported", c.reported, Style::new().fg(AMBER)),
            ("breach", c.breach, Style::new().fg(RED)),
            ("no source", g.no_source, Style::new().fg(DIM)),
        ] {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>9} ", fmt_num(n)), style),
                Span::styled(name, Style::new().fg(DIM)),
            ]));
        }
        if g.dropped > 0 {
            lines.push(Line::from(Span::styled(
                format!("{} shots over the cap", fmt_num(g.dropped)),
                Style::new().fg(ORANGE),
            )));
        }
        if !g.has_home() {
            lines.push(Line::from(Span::styled(
                "home country unknown: no arcs",
                Style::new().fg(ORANGE),
            )));
        }
        frame.render_widget(Paragraph::new(lines).block(panel_block("sources")), side);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let keys: &[(&str, &str)] = if self.editing_filter {
            &[
                ("type", "filter"),
                ("Enter/Esc", "done"),
                ("Bksp", "delete"),
            ]
        } else if self.view == View::Globe {
            &[
                ("q", "quit"),
                ("Tab/1-5", "view"),
                ("Space", "pause"),
                ("+/-", "speed"),
                ("m", "tuned"),
                ("l", "lock home"),
                ("r", "reload"),
            ]
        } else if self.detail {
            &[
                ("Esc", "back"),
                ("j/k", "next/prev"),
                ("Tab", "view"),
                ("q", "quit"),
            ]
        } else {
            &[
                ("q", "quit"),
                ("Tab/1-5", "view"),
                ("j/k", "move"),
                ("Enter", "detail"),
                ("/", "filter"),
                ("c", "category"),
                ("Esc", "back/clear"),
                ("r", "reload"),
            ]
        };
        let mut spans = Vec::new();
        for (k, v) in keys {
            spans.push(Span::styled(
                format!(" {k} "),
                Style::new().fg(BG).bg(AMBER),
            ));
            spans.push(Span::styled(format!(" {v}  "), Style::new().fg(DIM)));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

fn group_matches(g: &Group, needle: &str) -> bool {
    let hay = [
        g.rule_id.as_str(),
        g.rule_description.as_str(),
        g.id.as_str(),
        g.category.label(),
        g.tuning.label(),
        g.decision.reason.as_str(),
    ];
    hay.iter().any(|h| h.to_lowercase().contains(needle))
        || g.agents.iter().any(|a| a.to_lowercase().contains(needle))
        || g.breach_signals
            .iter()
            .any(|a| a.to_lowercase().contains(needle))
        || g.model.as_ref().is_some_and(|m| {
            m.tags.iter().any(|t| t.to_lowercase().contains(needle))
                || m.verdict.to_lowercase().contains(needle)
        })
}

fn panel_block(title_text: &str) -> Block<'static> {
    Block::bordered()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border())
        .title(Span::styled(
            format!(" {} ", title_text.trim().to_uppercase()),
            label(),
        ))
        .style(panel())
}

fn level_style(level: u32) -> Style {
    let c = match level {
        12.. => RED,
        8..=11 => ORANGE,
        5..=7 => AMBER,
        _ => DIM,
    };
    Style::new().fg(c).bold()
}

fn decision_span(g: &Group) -> Span<'static> {
    let health = if g.decision.health_failure { "!" } else { "" };
    if g.decision.delivery_required {
        let colour = if g.decision.health_failure {
            RED
        } else {
            AMBER
        };
        Span::styled(format!("DELIVER{health}"), Style::new().fg(colour).bold())
    } else {
        Span::styled(format!("held{health}"), Style::new().fg(DIM))
    }
}

fn agents_short(g: &Group) -> String {
    match g.agents.as_slice() {
        [] => "-".into(),
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} +{}", rest.len()),
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Run the TUI until the user quits.
pub fn run(source: SnapshotSource) -> std::io::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(std::io::Error::other(
            "the tui needs an interactive terminal; use `web` or run it in a terminal",
        ));
    }
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, App::new(source));
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, mut app: App) -> std::io::Result<()> {
    let mut last_poll = Instant::now();
    while !app.quit {
        terminal.draw(|f| app.render(f))?;
        let timeout = POLL_INTERVAL
            .saturating_sub(last_poll.elapsed())
            .min(Duration::from_millis(if app.view == View::Globe {
                50
            } else {
                250
            }));
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            app.handle_key(key);
        }
        if last_poll.elapsed() >= POLL_INTERVAL {
            app.poll();
            last_poll = Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo.json")
    }

    fn draw(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.render(f)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn assert_clean(screen: &str) {
        assert!(
            !screen
                .chars()
                .any(|c| c != '\n' && (c.is_control() || c == '\u{202E}')),
            "control character reached the terminal buffer"
        );
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn overview_shows_key_facts() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        let screen = draw(&mut app, 140, 40);
        assert!(screen.contains("SOC THIEF // NIGHT SHIFT"));
        assert!(screen.contains("DEMO DATA"));
        assert!(screen.contains("EVENTS"));
        assert!(screen.contains("PAGED"));
        assert!(screen.contains("brute force then success"));
        assert!(screen.contains("● LIVE"));
        assert_clean(&screen);
    }

    #[test]
    fn every_view_renders_without_leaking_escapes() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        for v in ['1', '2', '3', '4', '5'] {
            app.handle_key(key(KeyCode::Char(v)));
            for (w, h) in [(140, 40), (60, 20), (20, 8)] {
                assert_clean(&draw(&mut app, w, h));
            }
        }
        // Every group's detail view.
        app.handle_key(key(KeyCode::Char('2')));
        let n = app.visible_groups().len();
        app.handle_key(key(KeyCode::Enter));
        for _ in 0..n {
            assert_clean(&draw(&mut app, 120, 40));
            app.handle_key(key(KeyCode::Char('j')));
        }
    }

    #[test]
    fn groups_view_lists_in_digest_order_and_filters() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        app.handle_key(key(KeyCode::Char('2')));
        let screen = draw(&mut app, 160, 40);
        assert!(screen.contains("CATEGORY"));
        let failed = screen.find("FAILED").unwrap();
        let recurring = screen.rfind("RECURRING").unwrap();
        assert!(failed < recurring);

        app.handle_key(key(KeyCode::Char('/')));
        for c in "sshd".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        let visible = app.visible_groups();
        assert!(!visible.is_empty());
        let snap = app.source.snapshot().unwrap().clone();
        for i in &visible {
            assert!(group_matches(&snap.groups[*i], "sshd"));
        }
        app.handle_key(key(KeyCode::Esc));
        assert!(app.filter.is_empty());

        app.handle_key(key(KeyCode::Char('c')));
        assert_eq!(app.category, Some(Category::Failed));
        assert!(
            app.visible_groups()
                .iter()
                .all(|&i| snap.groups[i].category == Category::Failed)
        );
    }

    #[test]
    fn detail_labels_model_as_advisory() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        app.handle_key(key(KeyCode::Char('2')));
        app.handle_key(key(KeyCode::Enter));
        assert!(app.detail);
        let screen = draw(&mut app, 140, 40);
        assert!(screen.contains("ADVISORY — CANNOT SUPPRESS"));
        assert!(screen.contains("GROUP DETAIL"));
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.detail);
    }

    #[test]
    fn missing_file_shows_error_not_crash() {
        let mut app = App::new(SnapshotSource::new("/nonexistent/soc-thief/snapshot.json"));
        for v in ['1', '2', '3', '4', '5'] {
            app.handle_key(key(KeyCode::Char(v)));
            app.handle_key(key(KeyCode::Enter));
            app.handle_key(key(KeyCode::Char('j')));
            let screen = draw(&mut app, 100, 30);
            assert!(screen.contains("NO SNAPSHOT"));
            assert!(screen.contains("snapshot file not found"));
        }
    }

    #[test]
    fn capped_snapshot_says_showing_n_of_m() {
        let dir = std::env::temp_dir().join(format!("stc-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snapshot.json");
        let doc = include_str!("../../fixtures/demo.json").replacen(
            "\"groups\": 16,",
            "\"groups\": 11204,",
            1,
        );
        std::fs::write(&path, doc).unwrap();
        let mut app = App::new(SnapshotSource::new(&path));
        std::fs::remove_dir_all(&dir).unwrap();
        app.handle_key(key(KeyCode::Char('2')));
        let screen = draw(&mut app, 160, 30);
        assert!(screen.contains("showing 16 of 11,204 groups"), "{screen}");

        let mut plain = App::new(SnapshotSource::new(fixture()));
        plain.handle_key(key(KeyCode::Char('2')));
        assert!(!draw(&mut plain, 160, 30).contains("showing"));
    }

    #[test]
    fn quit_key() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.quit);
    }

    #[test]
    fn number_format() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(48213), "48,213");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }

    #[test]
    fn health_and_history_render() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        app.handle_key(key(KeyCode::Char('3')));
        let screen = draw(&mut app, 120, 30);
        assert!(screen.contains("collector"));
        app.handle_key(key(KeyCode::Char('4')));
        let screen = draw(&mut app, 120, 30);
        assert!(screen.contains("EARLIER WINDOWS"));
        assert!(screen.contains("2026-11-05 08:00"));
    }

    #[test]
    fn globe_view_draws_the_globe_panel_and_keys() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        app.handle_key(key(KeyCode::Char('5')));
        let screen = draw(&mut app, 140, 40);
        assert!(screen.contains("5 GLOBE"));
        assert!(screen.contains("HOME AU"));
        assert!(screen.contains("LAST HOUR BY SOURCE"));
        assert!(screen.contains("Space"));
        let braille = screen
            .chars()
            .filter(|c| ('\u{2801}'..='\u{28FF}').contains(c))
            .count();
        assert!(braille > 300, "only {braille} globe cells");
        assert_clean(&screen);

        let speed = app.globe.as_ref().unwrap().speed;
        app.handle_key(key(KeyCode::Char('+')));
        app.handle_key(key(KeyCode::Char(' ')));
        app.handle_key(key(KeyCode::Char('m')));
        app.handle_key(key(KeyCode::Char('l')));
        let g = app.globe.as_ref().unwrap();
        assert!(g.speed > speed && g.paused && !g.show_tuned && g.locked);
        assert!(draw(&mut app, 140, 40).contains("PAUSED"));
        // Globe keys do nothing elsewhere; 'q' still quits from the globe.
        app.handle_key(key(KeyCode::Char('1')));
        app.handle_key(key(KeyCode::Char('m')));
        assert!(!app.globe.as_ref().unwrap().show_tuned);
        app.handle_key(key(KeyCode::Char('5')));
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.quit);
    }

    #[test]
    fn globe_without_attacks_says_how_to_get_them() {
        let path =
            std::env::temp_dir().join(format!("soc-thief-globe-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"schema": "soc-thief.snapshot/1", "source": "demo"}"#,
        )
        .unwrap();
        let mut app = App::new(SnapshotSource::new(&path));
        app.handle_key(key(KeyCode::Char('5')));
        let screen = draw(&mut app, 100, 30);
        std::fs::remove_file(&path).unwrap();
        assert!(screen.contains("No attack data in this snapshot."));
        assert_clean(&screen);
    }

    #[test]
    fn tab_cycles_through_all_five_views() {
        let mut app = App::new(SnapshotSource::new(fixture()));
        for expected in [
            View::Groups,
            View::Health,
            View::History,
            View::Globe,
            View::Overview,
        ] {
            app.handle_key(key(KeyCode::Tab));
            assert_eq!(app.view, expected);
        }
        app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.view, View::Globe);
    }
}
