//! Watches one snapshot file by polling its modification time.
//!
//! A failed reload keeps the last good snapshot and marks it stale.

use crate::snapshot::{self, LoadError, Snapshot};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The last read succeeded.
    Live,
    /// The last read failed; an older good snapshot is still shown.
    Stale,
    /// Nothing good has ever been read.
    Unavailable,
}

pub struct SnapshotSource {
    path: PathBuf,
    /// (mtime, length) of the file at the last read attempt.
    seen: Option<(SystemTime, u64)>,
    snapshot: Option<Arc<Snapshot>>,
    error: Option<LoadError>,
    generation: u64,
}

impl SnapshotSource {
    /// Create a source and read the file once.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mut s = SnapshotSource {
            path: path.into(),
            seen: None,
            snapshot: None,
            error: None,
            generation: 0,
        };
        s.reload();
        s
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> Option<&Arc<Snapshot>> {
        self.snapshot.as_ref()
    }

    pub fn error(&self) -> Option<&LoadError> {
        self.error.as_ref()
    }

    /// Increases every time a read attempt changes what is shown.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn freshness(&self) -> Freshness {
        match (&self.snapshot, &self.error) {
            (Some(_), None) => Freshness::Live,
            (Some(_), Some(_)) => Freshness::Stale,
            (None, _) => Freshness::Unavailable,
        }
    }

    fn stamp(&self) -> Option<(SystemTime, u64)> {
        let m = std::fs::metadata(&self.path).ok()?;
        Some((m.modified().ok()?, m.len()))
    }

    /// Re-read if the file's mtime or size changed. Returns true if anything changed.
    pub fn poll(&mut self) -> bool {
        let stamp = self.stamp();
        if stamp.is_some() && stamp == self.seen {
            return false;
        }
        if stamp.is_none() && self.error == Some(LoadError::Missing) {
            return false;
        }
        self.reload();
        true
    }

    /// Read the file now, whatever its mtime.
    pub fn reload(&mut self) {
        self.seen = self.stamp();
        match snapshot::load(&self.path) {
            Ok(s) => {
                self.snapshot = Some(Arc::new(s));
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
        self.generation += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("stc-src-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn keeps_last_good_snapshot_when_reload_fails() {
        let dir = tmpdir("stale");
        let path = dir.join("snapshot.json");
        std::fs::write(&path, include_str!("../fixtures/demo.json")).unwrap();
        let mut src = SnapshotSource::new(&path);
        assert_eq!(src.freshness(), Freshness::Live);

        std::fs::write(&path, "{broken").unwrap();
        src.reload();
        assert_eq!(src.freshness(), Freshness::Stale);
        assert!(src.snapshot().is_some());
        assert!(matches!(src.error(), Some(LoadError::Json(_))));

        std::fs::write(&path, include_str!("../fixtures/demo.json")).unwrap();
        src.reload();
        assert_eq!(src.freshness(), Freshness::Live);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_unavailable_not_a_crash() {
        let mut src = SnapshotSource::new("/nonexistent/soc-thief/snapshot.json");
        assert_eq!(src.freshness(), Freshness::Unavailable);
        assert_eq!(src.error(), Some(&LoadError::Missing));
        assert!(!src.poll());
    }

    #[test]
    fn poll_notices_a_size_change() {
        let dir = tmpdir("poll");
        let path = dir.join("snapshot.json");
        std::fs::write(&path, r#"{"schema": "soc-thief.snapshot/1"}"#).unwrap();
        let mut src = SnapshotSource::new(&path);
        assert!(!src.poll());
        std::fs::write(&path, include_str!("../fixtures/demo.json")).unwrap();
        assert!(src.poll());
        assert!(src.snapshot().unwrap().is_demo());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
