//! The pew pew globe: a rotating two-colour globe that replays a snapshot's attack shots as
//! comets landing on home. Pure drawing over sanitised snapshot data; time comes in as an
//! argument, so tests drive the clock.

use super::theme::{AMBER, DIM, GREEN, RED, SEA};
use crate::snapshot::{Attacks, Shot, ShotKind};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use std::collections::{HashMap, VecDeque};
use std::f64::consts::PI;

include!("centroids.rs");
/// 720x360 bits, half a degree each, row 0 at 90N, column 0 at 180W. See scripts/build_globe_data.py.
static LAND: &[u8] = include_bytes!("land.bin");
const LAND_W: usize = 720;
const LAND_H: usize = 360;

pub const TILT: f64 = 20.0 * PI / 180.0;
const SPIN_SECONDS: f64 = 30.0;
pub const FLIGHT_SECONDS: f64 = 1.6;
const IMPACT_SECONDS: f64 = 0.6;
pub const ALARM_SECONDS: f64 = 3.0;
pub const MAX_ARCS: usize = 80;
const PATH_SAMPLES: usize = 48;
const TAIL: usize = 7;
const TICKER: usize = 8;
/// Sim seconds the "by source" panel covers.
pub const RECENT_SECONDS: f64 = 3600.0;
/// A whole window replays in about this many real seconds at the default speed.
const LOOP_SECONDS: f64 = 240.0;
pub const SPEEDS: [u32; 6] = [1, 10, 60, 360, 1440, 3600];
const BRAILLE: [[u8; 2]; 4] = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];

pub type V3 = [f64; 3];

fn land_bit(index: usize) -> bool {
    LAND[index >> 3] & (0x80 >> (index & 7)) != 0
}

#[cfg(test)]
pub fn is_land(lat: f64, lon: f64) -> bool {
    let row = (((90.0 - lat) * LAND_H as f64 / 180.0) as usize).min(LAND_H - 1);
    let col = (((lon + 180.0) * LAND_W as f64 / 360.0).floor() as i64).rem_euclid(LAND_W as i64);
    land_bit(row * LAND_W + col as usize)
}

/// The table's own `&'static str` for a code, so arcs can key on it.
fn centroid_entry(code: &str) -> Option<&'static (&'static str, f64, f64)> {
    CENTROIDS
        .binary_search_by(|entry| entry.0.cmp(code))
        .ok()
        .map(|i| &CENTROIDS[i])
}

pub fn centroid(code: &str) -> Option<(f64, f64)> {
    centroid_entry(code).map(|e| (e.1, e.2))
}

/// Globe frame: x towards 0N 0E, y towards 0N 90E, z towards the north pole.
pub fn unit(lat: f64, lon: f64) -> V3 {
    let (la, lo) = (lat.to_radians(), lon.to_radians());
    [la.cos() * lo.cos(), la.cos() * lo.sin(), la.sin()]
}

/// Spin by `phi` about the pole, then tilt the north pole `tilt` towards the viewer.
/// Returns screen (right, up, towards viewer). At phi=0, tilt=0, 0N 0E faces the viewer.
pub fn to_view(v: V3, phi: f64, tilt: f64) -> V3 {
    let [x, y, z] = v;
    let right = y * phi.cos() + x * phi.sin();
    let front = x * phi.cos() - y * phi.sin();
    [
        right,
        z * tilt.cos() - front * tilt.sin(),
        z * tilt.sin() + front * tilt.cos(),
    ]
}

/// The (phi, tilt) that puts a point at the centre of the disc.
pub fn facing(lat: f64, lon: f64) -> (f64, f64) {
    (-lon.to_radians(), lat.to_radians())
}

/// Draw order: a higher layer clears a cell, a lower one is dropped (a cell has one colour).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    Empty,
    Sea,
    Land,
    Tuned,
    Reported,
    Breach,
}

impl Layer {
    pub fn of(kind: ShotKind) -> Layer {
        match kind.shown() {
            ShotKind::Tuned => Layer::Tuned,
            ShotKind::Breach => Layer::Breach,
            _ => Layer::Reported,
        }
    }

    pub fn colour(self) -> Color {
        match self {
            Layer::Empty | Layer::Sea => SEA,
            Layer::Land => GREEN,
            Layer::Tuned => DIM,
            Layer::Reported => AMBER,
            Layer::Breach => RED,
        }
    }
}

/// A grid of Braille cells, 2x4 dots each, with one layer per cell.
pub struct Canvas {
    pub cols: usize,
    pub rows: usize,
    pub bits: Vec<u8>,
    pub layer: Vec<Layer>,
}

impl Canvas {
    pub fn new(cols: usize, rows: usize) -> Self {
        Canvas {
            cols,
            rows,
            bits: vec![0; cols * rows],
            layer: vec![Layer::Empty; cols * rows],
        }
    }

    pub fn dot(&mut self, x: i64, y: i64, layer: Layer) {
        if x < 0 || y < 0 || x >= (self.cols * 2) as i64 || y >= (self.rows * 4) as i64 {
            return;
        }
        let (x, y) = (x as usize, y as usize);
        let cell = (y / 4) * self.cols + x / 2;
        let old = self.layer[cell];
        if layer < old {
            return;
        }
        if layer > old {
            self.bits[cell] = 0;
            self.layer[cell] = layer;
        }
        self.bits[cell] |= BRAILLE[y & 3][x & 1];
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        for row in 0..self.rows.min(area.height as usize) {
            for col in 0..self.cols.min(area.width as usize) {
                let i = row * self.cols + col;
                if self.bits[i] == 0 {
                    continue;
                }
                let glyph = char::from_u32(0x2800 + self.bits[i] as u32).unwrap_or(' ');
                if let Some(cell) = buf.cell_mut((area.x + col as u16, area.y + row as u16)) {
                    cell.set_char(glyph).set_fg(self.layer[i].colour());
                }
            }
        }
    }
}

/// One sea dot per cell, staggered between neighbours, so water reads as texture.
fn sea_dot(x: usize, y: usize) -> bool {
    let odd = ((x >> 1) + (y >> 2)) & 1;
    (x & 1) == odd && (y & 3) == if odd == 1 { 3 } else { 1 }
}

/// The disc for one size and tilt, precomputed; each frame is a spin offset into the land grid.
pub struct Disc {
    cols: usize,
    rows: usize,
    tilt: f64,
    radius: f64,
    cx: f64,
    cy: f64,
    /// (x, y, land row offset, land column before the spin, sea texture dot)
    dots: Vec<(i64, i64, usize, f64, bool)>,
    rim: Vec<(i64, i64)>,
}

impl Disc {
    pub fn new(cols: usize, rows: usize, tilt: f64) -> Self {
        let (width, height) = ((cols * 2) as f64, (rows * 4) as f64);
        let radius = (width.min(height) / 2.0 / 1.2).max(1.0); // room for arcs over the rim
        let (cx, cy) = (width / 2.0, height / 2.0);
        let (mut dots, mut rim) = (Vec::new(), Vec::new());
        for y in 0..rows * 4 {
            for x in 0..cols * 2 {
                let sx = (x as f64 + 0.5 - cx) / radius;
                let sy = (cy - (y as f64 + 0.5)) / radius;
                let distance = sx.hypot(sy);
                if distance > 1.0 {
                    if distance * radius <= radius + 0.75 {
                        rim.push((x as i64, y as i64));
                    }
                    continue;
                }
                let sz = (1.0 - distance * distance).sqrt();
                let up = sy * tilt.cos() + sz * tilt.sin();
                let front = -sy * tilt.sin() + sz * tilt.cos();
                let lat = up.clamp(-1.0, 1.0).asin().to_degrees();
                let row = (((90.0 - lat) * LAND_H as f64 / 180.0) as usize).min(LAND_H - 1);
                let longitude = sx.atan2(front).to_degrees();
                dots.push((
                    x as i64,
                    y as i64,
                    row * LAND_W,
                    (longitude + 180.0) * LAND_W as f64 / 360.0,
                    sea_dot(x, y),
                ));
            }
        }
        Disc {
            cols,
            rows,
            tilt,
            radius,
            cx,
            cy,
            dots,
            rim,
        }
    }

    pub fn draw(&self, canvas: &mut Canvas, phi: f64) {
        let shift = phi.to_degrees() * LAND_W as f64 / 360.0;
        for &(x, y, row, column, sea) in &self.dots {
            let col = ((column - shift).floor() as i64).rem_euclid(LAND_W as i64) as usize;
            if land_bit(row + col) {
                canvas.dot(x, y, Layer::Land);
            } else if sea {
                canvas.dot(x, y, Layer::Sea);
            }
        }
        for &(x, y) in &self.rim {
            canvas.dot(x, y, Layer::Sea);
        }
    }

    /// Dot position of a point lofted by `scale`, or None when the globe hides it.
    pub fn screen(&self, v: V3, phi: f64, tilt: f64, scale: f64) -> Option<(i64, i64)> {
        let [right, up, toward] = to_view(v, phi, tilt).map(|c| c * scale);
        if toward < 0.0 && right * right + up * up <= 1.0 {
            return None;
        }
        Some((
            (self.cx + right * self.radius).floor() as i64,
            (self.cy - up * self.radius).floor() as i64,
        ))
    }
}

/// Great-circle samples from source to home, each with a loft scale above the surface.
pub fn arc_path(source: V3, home: V3) -> Vec<(V3, f64)> {
    let cosine = (0..3)
        .map(|i| source[i] * home[i])
        .sum::<f64>()
        .clamp(-1.0, 1.0);
    let omega = cosine.acos();
    if omega < 1e-3 {
        return vec![(home, 1.0)];
    }
    (0..=PATH_SAMPLES)
        .map(|step| {
            let s = step as f64 / PATH_SAMPLES as f64;
            let a = ((1.0 - s) * omega).sin() / omega.sin();
            let b = (s * omega).sin() / omega.sin();
            let point = [0, 1, 2].map(|i| a * source[i] + b * home[i]);
            let loft = 1.0 + (0.04 + 0.16 * omega / PI) * (PI * s).sin();
            (point, loft)
        })
        .collect()
}

struct Arc {
    country: &'static str,
    layer: Layer,
    born: f64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub events: u64,
    pub tuned: u64,
    pub reported: u64,
    pub breach: u64,
}

/// Replay state: a sim clock over the shots, live arcs, counters and a ticker.
pub struct Globe {
    shots: Vec<Shot>,
    pub home: String,
    home_point: Option<(f64, f64)>,
    paths: HashMap<&'static str, Vec<(V3, f64)>>,
    pub span: f64,
    pub no_source: u64,
    pub dropped: u64,
    pub speed: u32,
    pub show_tuned: bool,
    pub locked: bool,
    pub paused: bool,
    pub clock: f64,
    next: usize,
    last: Option<f64>,
    arcs: Vec<Arc>,
    impacts: Vec<(f64, Layer)>,
    pub counts: Counts,
    recent: VecDeque<(f64, String)>,
    pub countries: HashMap<String, u64>,
    pub ticker: VecDeque<Shot>,
    pub alarm: Option<(f64, String)>,
    disc: Option<Disc>,
    locked_disc: Option<Disc>,
}

impl Globe {
    pub fn new(attacks: &Attacks, span: f64) -> Self {
        let home_point = centroid(&attacks.home);
        let paths = match home_point {
            Some((lat, lon)) => CENTROIDS
                .iter()
                .map(|(code, a, b)| (*code, arc_path(unit(*a, *b), unit(lat, lon))))
                .collect(),
            None => HashMap::new(),
        };
        let last_shot = attacks.shots.last().map_or(0.0, |s| s.t);
        let span = span.max(last_shot).max(1.0);
        let speed = SPEEDS
            .iter()
            .copied()
            .find(|s| *s as f64 >= span / LOOP_SECONDS)
            .unwrap_or(SPEEDS[SPEEDS.len() - 1]);
        let mut globe = Globe {
            shots: attacks.shots.clone(),
            home: attacks.home.clone(),
            home_point,
            paths,
            span,
            no_source: attacks.no_source,
            dropped: attacks.dropped,
            speed,
            show_tuned: true,
            locked: false,
            paused: false,
            clock: 0.0,
            next: 0,
            last: None,
            arcs: Vec::new(),
            impacts: Vec::new(),
            counts: Counts::default(),
            recent: VecDeque::new(),
            countries: HashMap::new(),
            ticker: VecDeque::new(),
            alarm: None,
            disc: None,
            locked_disc: None,
        };
        globe.restart();
        globe
    }

    pub fn has_home(&self) -> bool {
        self.home_point.is_some()
    }

    fn restart(&mut self) {
        self.clock = 0.0;
        self.next = 0;
        self.arcs.clear();
        self.impacts.clear();
        self.counts = Counts::default();
        self.recent.clear();
        self.countries.clear();
        self.ticker.clear();
    }

    pub fn faster(&mut self) {
        if let Some(i) = SPEEDS.iter().position(|s| *s > self.speed) {
            self.speed = SPEEDS[i];
        }
    }

    pub fn slower(&mut self) {
        if let Some(s) = SPEEDS.iter().rev().find(|s| **s < self.speed) {
            self.speed = *s;
        }
    }

    /// Move the sim clock to real time `now` (seconds), launching every shot it passes.
    pub fn advance(&mut self, now: f64) {
        let elapsed = (now - self.last.unwrap_or(now)).clamp(0.0, 1.0);
        self.last = Some(now);
        if !self.paused {
            self.clock += elapsed * self.speed as f64;
        }
        if self.clock > self.span {
            self.restart();
        }
        while self.next < self.shots.len() && self.shots[self.next].t <= self.clock {
            let shot = self.shots[self.next].clone();
            self.launch(shot, now);
            self.next += 1;
        }
        while let Some((t, _)) = self.recent.front() {
            if *t >= self.clock - RECENT_SECONDS {
                break;
            }
            let (_, country) = self.recent.pop_front().unwrap_or_default();
            if let Some(n) = self.countries.get_mut(&country) {
                *n -= 1;
                if *n == 0 {
                    self.countries.remove(&country);
                }
            }
        }
        let (landed, flying): (Vec<Arc>, Vec<Arc>) = std::mem::take(&mut self.arcs)
            .into_iter()
            .partition(|arc| now - arc.born >= FLIGHT_SECONDS);
        self.arcs = flying;
        self.impacts
            .extend(landed.iter().map(|arc| (now, arc.layer)));
        self.impacts.retain(|(born, _)| now - born < IMPACT_SECONDS);
    }

    fn launch(&mut self, shot: Shot, now: f64) {
        let kind = shot.kind.shown();
        self.counts.events += 1;
        match kind {
            ShotKind::Tuned => self.counts.tuned += 1,
            ShotKind::Breach => self.counts.breach += 1,
            _ => self.counts.reported += 1,
        }
        if kind == ShotKind::Breach {
            self.alarm = Some((now, shot.label.clone()));
        }
        if !shot.country.is_empty() {
            self.recent.push_back((shot.t, shot.country.clone()));
            *self.countries.entry(shot.country.clone()).or_default() += 1;
        }
        let shown = self.show_tuned || kind != ShotKind::Tuned;
        if let Some(entry) = centroid_entry(&shot.country)
            && shown
            && self.paths.contains_key(entry.0)
            && self.arcs.len() < MAX_ARCS
        {
            self.arcs.push(Arc {
                country: entry.0,
                layer: Layer::of(shot.kind),
                born: now,
            });
        }
        if kind != ShotKind::Tuned {
            if self.ticker.len() == TICKER {
                self.ticker.pop_front();
            }
            self.ticker.push_back(shot);
        }
    }

    pub fn alarm_text(&self, now: f64) -> Option<&str> {
        self.alarm
            .as_ref()
            .filter(|(at, _)| now - at < ALARM_SECONDS)
            .map(|(_, text)| text.as_str())
    }

    fn view(&self, now: f64) -> (f64, f64) {
        match self.home_point {
            Some((lat, lon)) if self.locked => facing(lat, lon),
            _ => ((2.0 * PI * now / SPIN_SECONDS) % (2.0 * PI), TILT),
        }
    }

    /// The globe, its arcs and impacts for a `cols` x `rows` cell area at real time `now`.
    pub fn draw(&mut self, cols: usize, rows: usize, now: f64) -> Canvas {
        let mut canvas = Canvas::new(cols, rows);
        let (phi, tilt) = self.view(now);
        let slot = if tilt == TILT {
            &mut self.disc
        } else {
            &mut self.locked_disc
        };
        if !slot
            .as_ref()
            .is_some_and(|d| d.cols == cols && d.rows == rows && d.tilt == tilt)
        {
            *slot = Some(Disc::new(cols, rows, tilt));
        }
        let Some(disc) = slot.as_ref() else {
            return canvas;
        };
        disc.draw(&mut canvas, phi);
        for arc in &self.arcs {
            let path = &self.paths[arc.country];
            let head = ((now - arc.born) / FLIGHT_SECONDS * (path.len() - 1) as f64) as usize;
            for (point, scale) in &path[head.saturating_sub(TAIL)..=head.min(path.len() - 1)] {
                if let Some((x, y)) = disc.screen(*point, phi, tilt, *scale) {
                    canvas.dot(x, y, arc.layer);
                }
            }
        }
        if let Some((lat, lon)) = self.home_point
            && let Some((hx, hy)) = disc.screen(unit(lat, lon), phi, tilt, 1.0)
        {
            for (born, layer) in &self.impacts {
                let radius = 1.0 + 4.0 * (now - born) / IMPACT_SECONDS;
                for step in 0..16 {
                    let angle = step as f64 * PI / 8.0;
                    canvas.dot(
                        hx + (radius * angle.cos()) as i64,
                        hy + (radius * angle.sin()) as i64,
                        *layer,
                    );
                }
            }
        }
        canvas
    }

    /// Top source countries in the last `RECENT_SECONDS` of sim time, busiest first.
    pub fn top_countries(&self, n: usize) -> Vec<(String, u64)> {
        let mut top: Vec<(String, u64)> = self
            .countries
            .iter()
            .map(|(c, n)| (c.clone(), *n))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(n);
        top
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: V3, b: V3) -> bool {
        (0..3).all(|i| (a[i] - b[i]).abs() < 1e-9)
    }

    fn shot(t: f64, country: &str, kind: ShotKind, label: &str) -> Shot {
        Shot {
            t,
            country: country.into(),
            level: 5,
            kind,
            label: label.into(),
        }
    }

    fn attacks() -> Attacks {
        Attacks {
            home: "AU".into(),
            shots: vec![
                shot(1.0, "US", ShotKind::Tuned, "noise"),
                shot(2.0, "CN", ShotKind::Reported, "brute"),
                shot(3.0, "", ShotKind::Reported, "unknown source"),
                shot(4.0, "RU", ShotKind::Breach, "pwned"),
                shot(5.0, "LAN", ShotKind::Unknown, "inside"),
            ],
            ..Attacks::default()
        }
    }

    #[test]
    fn land_mask_knows_continents_from_oceans() {
        for (lat, lon) in [
            (23.0, 13.0),
            (-24.0, 134.0),
            (40.0, -100.0),
            (60.0, 90.0),
            (-80.0, 0.0),
        ] {
            assert!(is_land(lat, lon), "{lat} {lon}");
        }
        for (lat, lon) in [(0.0, -150.0), (-40.0, -30.0), (-30.0, 80.0), (0.0, 0.0)] {
            assert!(!is_land(lat, lon), "{lat} {lon}");
        }
        assert_eq!(centroid("AU"), Some((-24.1, 134.0)));
        assert_eq!(centroid("TW"), Some((23.7, 120.9)));
        assert_eq!(centroid("LAN"), None);
        assert!(
            CENTROIDS.windows(2).all(|w| w[0].0 < w[1].0),
            "binary search needs order"
        );
    }

    #[test]
    fn view_faces_zero_zero_east_is_right_and_facing_centres() {
        assert!(close(to_view(unit(0.0, 0.0), 0.0, 0.0), [0.0, 0.0, 1.0]));
        assert!((to_view(unit(0.0, 90.0), 0.0, 0.0)[0] - 1.0).abs() < 1e-9);
        for (lat, lon) in [(-24.1, 134.0), (61.4, 9.7), (-50.0, -70.0)] {
            let (phi, tilt) = facing(lat, lon);
            assert!(close(to_view(unit(lat, lon), phi, tilt), [0.0, 0.0, 1.0]));
        }
    }

    #[test]
    fn disc_shows_the_land_that_faces_the_viewer() {
        let disc = Disc::new(40, 20, 0.0);
        for (lon, layer) in [(20.0, Layer::Land), (-150.0, Layer::Sea)] {
            let mut canvas = Canvas::new(40, 20);
            disc.draw(&mut canvas, -f64::to_radians(lon));
            assert_eq!(canvas.layer[10 * 40 + 20], layer, "lon {lon}");
        }
    }

    #[test]
    fn arc_runs_source_to_home_and_lofts_in_the_middle() {
        let (from, to) = (unit(39.5, -97.5), unit(-24.1, 134.0));
        let path = arc_path(from, to);
        assert!(close(path[0].0, from) && close(path[path.len() - 1].0, to));
        assert!((path[0].1 - 1.0).abs() < 1e-9);
        assert!(path[path.len() / 2].1 > 1.05);
        assert_eq!(arc_path(to, to).len(), 1);
    }

    #[test]
    fn hidden_behind_the_globe_unless_lofted_past_the_rim() {
        let disc = Disc::new(40, 20, 0.0);
        assert!(disc.screen(unit(0.0, 0.0), 0.0, 0.0, 1.0).is_some());
        assert!(disc.screen(unit(0.0, 180.0), 0.0, 0.0, 1.0).is_none());
        assert!(disc.screen(unit(0.0, 100.0), 0.0, 0.0, 1.15).is_some());
    }

    #[test]
    fn a_cell_shows_one_colour_and_arcs_win() {
        let mut canvas = Canvas::new(1, 1);
        canvas.dot(0, 0, Layer::Sea);
        canvas.dot(1, 0, Layer::Land);
        assert_eq!((canvas.layer[0], canvas.bits[0]), (Layer::Land, 0x08));
        canvas.dot(0, 1, Layer::Sea);
        assert_eq!(canvas.bits[0], 0x08);
        canvas.dot(0, 3, Layer::Reported);
        canvas.dot(1, 3, Layer::Tuned);
        assert_eq!((canvas.layer[0], canvas.bits[0]), (Layer::Reported, 0x40));
        canvas.dot(5, 5, Layer::Breach);
        canvas.dot(-1, 0, Layer::Breach);
        assert_eq!(canvas.layer[0], Layer::Reported);
    }

    #[test]
    fn replay_launches_counts_alarms_and_loops() {
        let mut globe = Globe::new(&attacks(), 10.0);
        globe.speed = 1;
        globe.advance(0.0);
        globe.advance(1.0);
        globe.advance(2.0);
        globe.advance(3.0);
        assert_eq!(globe.counts.events, 3);
        assert_eq!(globe.arcs.len(), 1); // US landed already; CN in flight
        let ticker: Vec<&str> = globe.ticker.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(ticker, ["brute", "unknown source"]);
        globe.advance(4.0);
        globe.advance(5.0);
        assert_eq!((globe.counts.breach, globe.counts.reported), (1, 3));
        assert_eq!(globe.alarm_text(5.0), Some("pwned"));
        assert_eq!(globe.alarm_text(4.0 + ALARM_SECONDS), None);
        assert_eq!(globe.countries.get("LAN"), Some(&1));
        assert_eq!(globe.countries.len(), 4);
        for now in 6..=11 {
            globe.advance(now as f64);
        }
        assert_eq!(globe.counts.events, 0, "restarted after the window");
    }

    #[test]
    fn hiding_tuned_drops_their_arcs_but_counts_them() {
        let mut globe = Globe::new(&attacks(), 10.0);
        globe.speed = 1;
        globe.show_tuned = false;
        globe.advance(0.0);
        globe.advance(1.5);
        assert_eq!((globe.counts.tuned, globe.arcs.len()), (1, 0));
    }

    #[test]
    fn arcs_draw_in_their_colour_then_land_as_impacts() {
        let mut globe = Globe::new(&attacks(), 10.0);
        globe.speed = 1;
        globe.locked = true;
        globe.advance(0.0);
        globe.advance(1.0);
        globe.advance(2.0);
        let layers = globe.draw(60, 24, 2.3).layer;
        for layer in [Layer::Land, Layer::Sea, Layer::Reported] {
            assert!(layers.contains(&layer), "{layer:?}");
        }
        globe.advance(2.0 + FLIGHT_SECONDS);
        assert!(globe.arcs.is_empty());
        assert!(!globe.impacts.is_empty());
        assert!(
            globe
                .draw(60, 24, 2.1 + FLIGHT_SECONDS)
                .layer
                .contains(&Layer::Reported)
        );
    }

    #[test]
    fn unknown_home_spins_without_arcs_and_speeds_step() {
        let mut no_home = attacks();
        no_home.home = String::new();
        let mut globe = Globe::new(&no_home, 86_400.0);
        assert!(!globe.has_home());
        assert_eq!(globe.speed, 360);
        globe.faster();
        assert_eq!(globe.speed, 1440);
        globe.slower();
        globe.slower();
        assert_eq!(globe.speed, 60);
        globe.advance(0.0);
        globe.advance(1.0);
        assert!(globe.arcs.is_empty());
        assert!(globe.draw(30, 10, 1.0).layer.contains(&Layer::Land));
    }
}
