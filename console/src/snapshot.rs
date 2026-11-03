//! The snapshot contract (`docs/SNAPSHOT.md`): types, loading and sanitising.
//!
//! Every string in a snapshot came from alert fields and is attacker-controlled.
//! `load` sanitises the whole document once, right after parsing, so nothing
//! downstream (TUI or web) ever sees a raw string.

use serde::{Deserialize, Deserializer, Serialize};
use std::cmp::Ordering;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The console refuses any snapshot bigger than this.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The only major schema version this console understands.
pub const SCHEMA_PREFIX: &str = "soc-thief.snapshot/";
pub const SCHEMA_MAJOR: &str = "1";

/// Caps, in characters, for displayed strings.
pub const CAP_SHORT: usize = 64;
pub const CAP_TEXT: usize = 300;
/// Caps on list lengths, so a hostile file cannot make the UI do unbounded work.
pub const CAP_GROUPS: usize = 5000;
pub const CAP_AGENTS: usize = 32;
pub const CAP_TAGS: usize = 16;
pub const CAP_LIST: usize = 200;
pub const CAP_TIMELINE: usize = 24 * 31;
pub const CAP_HISTORY: usize = 30;

fn nd<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Attention,
    Failed,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Attention => "ATTENTION",
            Status::Failed => "FAILED",
            Status::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Failed,
    New,
    Spike,
    Recurring,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Category {
    pub const ALL: [Category; 4] = [
        Category::Failed,
        Category::New,
        Category::Spike,
        Category::Recurring,
    ];

    /// Digest order: failed, new, spike, recurring, then anything unrecognised.
    pub fn rank(self) -> u8 {
        match self {
            Category::Failed => 0,
            Category::New => 1,
            Category::Spike => 2,
            Category::Recurring => 3,
            Category::Unknown => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Failed => "FAILED",
            Category::New => "NEW",
            Category::Spike => "SPIKE",
            Category::Recurring => "RECURRING",
            Category::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tuning {
    #[default]
    None,
    Low,
    Mute,
    #[serde(other)]
    Unknown,
}

impl Tuning {
    pub fn label(self) -> &'static str {
        match self {
            Tuning::None => "none",
            Tuning::Low => "low",
            Tuning::Mute => "mute",
            Tuning::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Demo,
    State,
    #[default]
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    #[serde(default, deserialize_with = "nd")]
    pub generated_at: String,
    #[serde(default, deserialize_with = "nd")]
    pub source: Source,
    #[serde(default, deserialize_with = "nd")]
    pub timezone: String,
    #[serde(default, deserialize_with = "nd")]
    pub window: Window,
    #[serde(default, deserialize_with = "nd")]
    pub health: Health,
    #[serde(default, deserialize_with = "nd")]
    pub groups: Vec<Group>,
    #[serde(default, deserialize_with = "nd")]
    pub breaches: Vec<Breach>,
    #[serde(default, deserialize_with = "nd")]
    pub timeline: Vec<Bucket>,
    #[serde(default, deserialize_with = "nd")]
    pub history: Vec<HistoryRow>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Window {
    #[serde(default, deserialize_with = "nd")]
    pub start: String,
    #[serde(default, deserialize_with = "nd")]
    pub end: String,
    #[serde(default, deserialize_with = "nd")]
    pub events: u64,
    #[serde(default, deserialize_with = "nd")]
    pub groups: u64,
    #[serde(default, deserialize_with = "nd")]
    pub duplicates: u64,
    #[serde(default, deserialize_with = "nd")]
    pub muted_by_tuning: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Health {
    #[serde(default, deserialize_with = "nd")]
    pub status: Status,
    #[serde(default, deserialize_with = "nd")]
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Check {
    #[serde(default, deserialize_with = "nd")]
    pub name: String,
    #[serde(default, deserialize_with = "nd")]
    pub status: Status,
    #[serde(default, deserialize_with = "nd")]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Group {
    #[serde(default, deserialize_with = "nd")]
    pub id: String,
    #[serde(default, deserialize_with = "nd")]
    pub rule_id: String,
    #[serde(default, deserialize_with = "nd")]
    pub rule_description: String,
    #[serde(default, deserialize_with = "nd")]
    pub level: u32,
    #[serde(default, deserialize_with = "nd")]
    pub count: u64,
    #[serde(default, deserialize_with = "nd")]
    pub agents: Vec<String>,
    #[serde(default, deserialize_with = "nd")]
    pub first_seen: String,
    #[serde(default, deserialize_with = "nd")]
    pub last_seen: String,
    #[serde(default, deserialize_with = "nd")]
    pub category: Category,
    #[serde(default, deserialize_with = "nd")]
    pub protected: bool,
    #[serde(default, deserialize_with = "nd")]
    pub tuning: Tuning,
    #[serde(default, deserialize_with = "nd")]
    pub decision: Decision,
    #[serde(default)]
    pub model: Option<Model>,
    #[serde(default, deserialize_with = "nd")]
    pub breach_signals: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Decision {
    #[serde(default, deserialize_with = "nd")]
    pub delivery_required: bool,
    #[serde(default, deserialize_with = "nd")]
    pub health_failure: bool,
    #[serde(default, deserialize_with = "nd")]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Model {
    #[serde(default, deserialize_with = "nd")]
    pub name: String,
    #[serde(default, deserialize_with = "nd")]
    pub verdict: String,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default, deserialize_with = "nd")]
    pub tags: Vec<String>,
    #[serde(default, deserialize_with = "nd")]
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Breach {
    #[serde(default, deserialize_with = "nd")]
    pub name: String,
    #[serde(default, deserialize_with = "nd")]
    pub signals: Vec<String>,
    #[serde(default, deserialize_with = "nd")]
    pub agent: String,
    #[serde(default, deserialize_with = "nd")]
    pub at: String,
    #[serde(default, deserialize_with = "nd")]
    pub paged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bucket {
    #[serde(default, deserialize_with = "nd")]
    pub start: String,
    #[serde(default, deserialize_with = "nd")]
    pub events: u64,
    #[serde(default, deserialize_with = "nd")]
    pub delivery_required: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryRow {
    #[serde(default, deserialize_with = "nd")]
    pub start: String,
    #[serde(default, deserialize_with = "nd")]
    pub end: String,
    #[serde(default, deserialize_with = "nd")]
    pub events: u64,
    #[serde(default, deserialize_with = "nd")]
    pub groups: u64,
    #[serde(default, deserialize_with = "nd")]
    pub delivered: bool,
    #[serde(default, deserialize_with = "nd")]
    pub health_failure: bool,
}

/// Why a snapshot was refused. Messages are safe to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Missing,
    Io(String),
    TooLarge(u64),
    Json(String),
    Schema(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Missing => write!(f, "snapshot file not found"),
            LoadError::Io(e) => write!(f, "cannot read snapshot: {e}"),
            LoadError::TooLarge(n) => {
                write!(f, "snapshot is {n} bytes; the limit is {MAX_BYTES} bytes")
            }
            LoadError::Json(e) => write!(f, "snapshot is not valid JSON for this format: {e}"),
            LoadError::Schema(s) => write!(
                f,
                "unsupported snapshot schema \"{s}\"; this console reads {SCHEMA_PREFIX}{SCHEMA_MAJOR}"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read, size-check, parse and sanitise a snapshot file.
pub fn load(path: &Path) -> Result<Snapshot, LoadError> {
    let file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => LoadError::Missing,
        _ => LoadError::Io(sanitize(&e.to_string(), CAP_TEXT)),
    })?;
    let len = file
        .metadata()
        .map_err(|e| LoadError::Io(sanitize(&e.to_string(), CAP_TEXT)))?
        .len();
    if len > MAX_BYTES {
        return Err(LoadError::TooLarge(len));
    }
    // The file can grow between metadata and read; never read past the limit.
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| LoadError::Io(sanitize(&e.to_string(), CAP_TEXT)))?;
    parse(&bytes)
}

/// Parse and sanitise snapshot bytes.
pub fn parse(bytes: &[u8]) -> Result<Snapshot, LoadError> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(LoadError::TooLarge(bytes.len() as u64));
    }
    #[derive(Deserialize)]
    struct Head {
        schema: Option<String>,
    }
    let head: Head = serde_json::from_slice(bytes).map_err(json_err)?;
    let schema = head.schema.unwrap_or_default();
    if !schema_supported(&schema) {
        return Err(LoadError::Schema(sanitize(&schema, CAP_SHORT)));
    }
    let mut snap: Snapshot = serde_json::from_slice(bytes).map_err(json_err)?;
    snap.sanitize();
    Ok(snap)
}

fn json_err(e: serde_json::Error) -> LoadError {
    // serde_json messages can quote input (e.g. unknown variants); sanitise them too.
    LoadError::Json(sanitize(&e.to_string(), CAP_TEXT))
}

/// `soc-thief.snapshot/1` and `soc-thief.snapshot/1.N` are accepted; any other major is not.
pub fn schema_supported(schema: &str) -> bool {
    match schema.strip_prefix(SCHEMA_PREFIX) {
        Some(version) => version.split('.').next() == Some(SCHEMA_MAJOR),
        None => false,
    }
}

/// Characters that are never drawn: C0/C1 controls (including ESC and DEL),
/// bidirectional overrides and zero-width formatting characters.
fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}')
}

/// Strip control and formatting characters, collapse whitespace runs to one space,
/// and cap the result at `max` characters (with a trailing ellipsis when cut).
pub fn sanitize(input: &str, max: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max * 4));
    let mut count = 0;
    let mut last_space = false;
    for c in input.chars() {
        let c = if c == '\t' || c == '\n' || c == '\r' {
            ' '
        } else {
            c
        };
        if is_forbidden(c) {
            continue;
        }
        if c.is_whitespace() {
            if last_space {
                continue;
            }
            last_space = true;
            let c = ' ';
            if count == max {
                out.pop();
                out.push('…');
                return out;
            }
            out.push(c);
        } else {
            last_space = false;
            if count == max {
                out.pop();
                out.push('…');
                return out;
            }
            out.push(c);
        }
        count += 1;
    }
    out.trim().to_string()
}

fn clean(s: &mut String, max: usize) {
    *s = sanitize(s, max);
}

fn clean_list(list: &mut Vec<String>, max_items: usize, max_len: usize) {
    let total = list.len();
    list.truncate(max_items);
    for s in list.iter_mut() {
        clean(s, max_len);
    }
    if total > max_items {
        list.push(format!("+{} more", total - max_items));
    }
}

impl Snapshot {
    fn sanitize(&mut self) {
        clean(&mut self.schema, CAP_SHORT);
        clean(&mut self.generated_at, CAP_SHORT);
        clean(&mut self.timezone, CAP_SHORT);
        clean(&mut self.window.start, CAP_SHORT);
        clean(&mut self.window.end, CAP_SHORT);

        self.health.checks.truncate(CAP_LIST);
        for c in &mut self.health.checks {
            clean(&mut c.name, CAP_SHORT);
            clean(&mut c.detail, CAP_TEXT);
        }

        self.groups.truncate(CAP_GROUPS);
        for g in &mut self.groups {
            clean(&mut g.id, CAP_SHORT);
            clean(&mut g.rule_id, CAP_SHORT);
            clean(&mut g.rule_description, CAP_TEXT);
            clean_list(&mut g.agents, CAP_AGENTS, CAP_SHORT);
            clean(&mut g.first_seen, CAP_SHORT);
            clean(&mut g.last_seen, CAP_SHORT);
            clean(&mut g.decision.reason, CAP_TEXT);
            clean_list(&mut g.breach_signals, CAP_TAGS, CAP_SHORT);
            if let Some(m) = &mut g.model {
                clean(&mut m.name, CAP_SHORT);
                clean(&mut m.verdict, CAP_SHORT);
                clean_list(&mut m.tags, CAP_TAGS, CAP_SHORT);
                clean(&mut m.summary, CAP_TEXT);
                m.confidence = m
                    .confidence
                    .filter(|c| c.is_finite())
                    .map(|c| c.clamp(0.0, 1.0));
            }
        }
        sort_digest(&mut self.groups);

        self.breaches.truncate(CAP_LIST);
        for b in &mut self.breaches {
            clean(&mut b.name, CAP_TEXT);
            clean_list(&mut b.signals, CAP_TAGS, CAP_SHORT);
            clean(&mut b.agent, CAP_SHORT);
            clean(&mut b.at, CAP_SHORT);
        }

        self.timeline.truncate(CAP_TIMELINE);
        for t in &mut self.timeline {
            clean(&mut t.start, CAP_SHORT);
        }

        self.history.truncate(CAP_HISTORY);
        for h in &mut self.history {
            clean(&mut h.start, CAP_SHORT);
            clean(&mut h.end, CAP_SHORT);
        }
    }

    /// `Some((listed, total))` when the snapshot lists fewer groups than the window had.
    /// The writer caps `groups` at 5000 and keeps `window.groups` as the true total.
    pub fn groups_capped(&self) -> Option<(usize, u64)> {
        let listed = self.groups.len();
        (self.window.groups > listed as u64).then_some((listed, self.window.groups))
    }

    pub fn is_demo(&self) -> bool {
        self.source == Source::Demo
    }
}

/// Digest order: category (failed, new, spike, recurring), then level desc, count desc.
/// Rule and id break ties so the order is stable across reloads.
pub fn digest_cmp(a: &Group, b: &Group) -> Ordering {
    a.category
        .rank()
        .cmp(&b.category.rank())
        .then(b.level.cmp(&a.level))
        .then(b.count.cmp(&a.count))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
        .then_with(|| a.id.cmp(&b.id))
}

pub fn sort_digest(groups: &mut [Group]) {
    groups.sort_by(digest_cmp);
}

/// Short display form of an RFC 3339 time: `2026-11-07 03:52`. Falls back to the input.
pub fn short_time(t: &str) -> String {
    let b = t.as_bytes();
    if b.len() >= 16 && b[10] == b'T' && t.is_char_boundary(16) {
        format!("{} {}", &t[..10], &t[11..16])
    } else {
        t.to_string()
    }
}

/// Hour of an RFC 3339 time, `HH`, for chart axes.
pub fn hour_of(t: &str) -> String {
    if t.len() >= 13 && t.as_bytes()[10] == b'T' && t.is_char_boundary(13) {
        t[11..13].to_string()
    } else {
        "??".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../fixtures/demo.json");

    #[test]
    fn demo_fixture_parses() {
        let s = parse(DEMO.as_bytes()).expect("demo fixture is valid");
        assert!(s.is_demo());
        assert_eq!(s.timeline.len(), 24);
        assert_eq!(s.history.len(), 7);
        assert!(s.groups.len() >= 15);
        assert!(s.groups.iter().any(|g| g.model.is_none()));
        assert!(s.groups.iter().any(|g| g.protected));
        assert!(s.breaches.iter().any(|b| b.paged));
        for c in Category::ALL {
            assert!(s.groups.iter().any(|g| g.category == c), "{c:?} missing");
        }
        for t in [Tuning::None, Tuning::Low, Tuning::Mute] {
            assert!(s.groups.iter().any(|g| g.tuning == t), "{t:?} missing");
        }
    }

    #[test]
    fn contract_example_parses() {
        let doc = r#"{
          "schema": "soc-thief.snapshot/1",
          "generated_at": "2026-11-07T08:00:04+11:00",
          "source": "state",
          "window": {"start": "a", "end": "b", "events": 1, "groups": 1, "duplicates": 0, "muted_by_tuning": 0},
          "health": {"status": "ok", "checks": []},
          "groups": [{"id": "c-1", "rule_id": "5712", "rule_description": null, "level": 10,
                      "count": 3, "agents": [], "category": "spike", "protected": true,
                      "tuning": "none", "decision": {"delivery_required": true,
                      "health_failure": false, "reason": "protected"}, "model": null,
                      "breach_signals": []}],
          "breaches": [], "timeline": [], "history": []
        }"#;
        let s = parse(doc.as_bytes()).unwrap();
        assert!(!s.is_demo());
        assert_eq!(s.groups[0].rule_description, "");
        assert!(s.groups[0].model.is_none());
    }

    #[test]
    fn oversize_is_refused() {
        let big = vec![b' '; (MAX_BYTES + 1) as usize];
        assert_eq!(parse(&big).unwrap_err(), LoadError::TooLarge(MAX_BYTES + 1));
    }

    #[test]
    fn oversize_file_is_refused_before_reading() {
        let dir = std::env::temp_dir().join(format!("stc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.json");
        let f = File::create(&path).unwrap();
        f.set_len(MAX_BYTES + 10).unwrap();
        let err = load(&path).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(err, LoadError::TooLarge(MAX_BYTES + 10));
    }

    #[test]
    fn missing_file_is_reported() {
        assert_eq!(
            load(Path::new("/nonexistent/soc-thief/snapshot.json")).unwrap_err(),
            LoadError::Missing
        );
    }

    #[test]
    fn wrong_schema_is_refused() {
        for s in [
            r#"{"schema": "soc-thief.snapshot/2"}"#,
            r#"{"schema": "soc-thief.snapshot/10"}"#,
            r#"{"schema": "other/1"}"#,
            r#"{}"#,
        ] {
            assert!(
                matches!(parse(s.as_bytes()), Err(LoadError::Schema(_))),
                "{s}"
            );
        }
        assert!(parse(br#"{"schema": "soc-thief.snapshot/1.3"}"#).is_ok());
    }

    #[test]
    fn invalid_json_is_refused() {
        assert!(matches!(parse(b"{not json"), Err(LoadError::Json(_))));
        assert!(matches!(parse(b"[]"), Err(LoadError::Json(_))));
    }

    #[test]
    fn unknown_fields_and_values_are_ignored() {
        let doc = r#"{"schema": "soc-thief.snapshot/1", "future": {"x": 1},
            "window": {"events": 5, "new_thing": true},
            "health": {"status": "melting", "checks": []},
            "groups": [{"id": "g", "category": "weird", "tuning": "maybe", "extra": [1,2]}]}"#;
        let s = parse(doc.as_bytes()).unwrap();
        assert_eq!(s.window.events, 5);
        assert_eq!(s.health.status, Status::Unknown);
        assert_eq!(s.groups[0].category, Category::Unknown);
        assert_eq!(s.groups[0].tuning, Tuning::Unknown);
    }

    #[test]
    fn hostile_strings_are_sanitised() {
        let doc = format!(
            r#"{{"schema": "soc-thief.snapshot/1", "groups": [{{
              "id": "x\u001b]0;pwned\u0007",
              "rule_description": "\u001b[2J\u001b[31mRED\u009b31m\u202Eevil\u200B {}",
              "agents": ["web-01\r\nFAKE LINE"],
              "model": {{"summary": "<script>alert(1)</script>", "confidence": 7.5}}
            }}]}}"#,
            "A".repeat(5000)
        );
        let s = parse(doc.as_bytes()).unwrap();
        let g = &s.groups[0];
        let all = format!("{}{}{}", g.id, g.rule_description, g.agents.join(""));
        assert!(!all.chars().any(|c| c.is_control()), "control char leaked");
        assert!(!all.contains('\u{202E}') && !all.contains('\u{200B}'));
        assert!(g.rule_description.chars().count() <= CAP_TEXT);
        assert!(g.rule_description.ends_with('…'));
        assert_eq!(g.agents[0], "web-01 FAKE LINE");
        // HTML is left as text; the web view uses textContent, the TUI cannot run it.
        let m = g.model.as_ref().unwrap();
        assert_eq!(m.summary, "<script>alert(1)</script>");
        assert_eq!(m.confidence, Some(1.0));
    }

    #[test]
    fn sanitize_caps_and_strips() {
        assert_eq!(sanitize("a\u{1b}[31mb", 10), "a[31mb");
        assert_eq!(sanitize("abcdef", 3), "ab…");
        assert_eq!(sanitize("  a \t\n b  ", 10), "a b");
        assert_eq!(sanitize("héllo", 5), "héllo");
    }

    #[test]
    fn long_lists_are_capped() {
        let agents: Vec<String> = (0..100).map(|i| format!("\"h{i}\"")).collect();
        let doc = format!(
            r#"{{"schema": "soc-thief.snapshot/1", "groups": [{{"agents": [{}]}}]}}"#,
            agents.join(",")
        );
        let s = parse(doc.as_bytes()).unwrap();
        assert_eq!(s.groups[0].agents.len(), CAP_AGENTS + 1);
        assert_eq!(s.groups[0].agents.last().unwrap(), "+68 more");
    }

    fn g(cat: Category, level: u32, count: u64, id: &str) -> Group {
        Group {
            id: id.into(),
            category: cat,
            level,
            count,
            ..Group::default()
        }
    }

    #[test]
    fn digest_order() {
        let mut groups = vec![
            g(Category::Recurring, 15, 9999, "r"),
            g(Category::Spike, 5, 10, "s-low"),
            g(Category::New, 3, 1, "n"),
            g(Category::Spike, 12, 1, "s-high"),
            g(Category::Unknown, 15, 1, "u"),
            g(Category::Failed, 1, 1, "f"),
            g(Category::Spike, 5, 50, "s-low-big"),
        ];
        sort_digest(&mut groups);
        let ids: Vec<&str> = groups.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, ["f", "n", "s-high", "s-low-big", "s-low", "r", "u"]);
    }

    #[test]
    fn load_sorts_groups_in_digest_order() {
        let s = parse(DEMO.as_bytes()).unwrap();
        assert!(
            s.groups
                .windows(2)
                .all(|w| digest_cmp(&w[0], &w[1]) != Ordering::Greater)
        );
    }

    #[test]
    fn capped_group_list_is_detected() {
        let mut s = parse(DEMO.as_bytes()).unwrap();
        assert_eq!(s.groups_capped(), None);
        s.window.groups = 11204;
        assert_eq!(s.groups_capped(), Some((s.groups.len(), 11204)));
    }

    #[test]
    fn time_helpers() {
        assert_eq!(short_time("2026-11-07T03:52:02+11:00"), "2026-11-07 03:52");
        assert_eq!(short_time("junk"), "junk");
        assert_eq!(hour_of("2026-11-07T03:52:02+11:00"), "03");
        assert_eq!(hour_of("é"), "??");
    }
}
