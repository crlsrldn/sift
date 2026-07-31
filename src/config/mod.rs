//! Configuration loading, merging, and validation (FR-22 … FR-25, spec §8).
//!
//! # Two-layer design
//!
//! [`RawConfig`] mirrors the TOML file exactly: every field is an `Option`, and
//! every struct carries `deny_unknown_fields`. [`Config`] is the resolved
//! result with concrete values.
//!
//! Keeping the raw layer around after resolution is what makes FR-23's
//! provenance reporting honest — "was this value written by the user or is it a
//! default?" is answered by asking whether the raw `Option` was `Some`, rather
//! than by comparing against the default and guessing (which cannot distinguish
//! "user wrote 7" from "user wrote nothing and the default is 7").

pub mod bytesize;
pub mod defaults;

use crate::risk::Risk;
use crate::{paths, Result, SiftError};
use bytesize::ByteSize;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Raw file representation
// ---------------------------------------------------------------------------

/// The config file as written. Unknown keys are **errors, not warnings**
/// (spec §8) — a typo like `min_age_day` silently falling back to a 14-day
/// default is exactly the kind of quiet failure that gets data deleted.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub general: Option<RawGeneral>,
    pub safety: Option<RawSafety>,
    pub projects: Option<RawProjects>,
    pub schedule: Option<RawSchedule>,
    pub scanners: Option<BTreeMap<String, RawScanner>>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGeneral {
    pub max_risk: Option<String>,
    pub max_bytes_per_run: Option<ByteSize>,
    pub quarantine_ttl_days: Option<u32>,
    pub free_space_floor: Option<ByteSize>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSafety {
    pub active_window_minutes: Option<u32>,
    pub max_walk_depth: Option<usize>,
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProjects {
    pub roots: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSchedule {
    pub hour: Option<u32>,
    pub minute: Option<u32>,
    pub skip_on_battery_below: Option<u8>,
    pub notify_threshold: Option<ByteSize>,
    pub max_days_between_runs: Option<u32>,
}

/// Per-scanner settings.
///
/// Scanner-specific keys (`urgency`, `autoremove`, `prefer_delegation`) are
/// declared here so `deny_unknown_fields` accepts them, and validation then
/// rejects them on scanners that do not use them. Without that second check,
/// `[scanners.logs] urgency = 4` would parse silently and do nothing.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawScanner {
    pub enabled: Option<bool>,
    pub min_age_days: Option<u32>,
    pub urgency: Option<u8>,
    pub autoremove: Option<bool>,
    pub prefer_delegation: Option<bool>,
}

// ---------------------------------------------------------------------------
// Resolved configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub general: General,
    pub safety: Safety,
    pub projects: Projects,
    pub schedule: Schedule,
    pub scanners: BTreeMap<String, ScannerConfig>,
    /// Where this came from, or `None` if no file existed.
    pub source: Option<PathBuf>,
    /// Retained for provenance reporting (FR-23).
    raw: RawConfig,
}

#[derive(Debug, Clone)]
pub struct General {
    pub max_risk: Risk,
    pub max_bytes_per_run: ByteSize,
    pub quarantine_ttl_days: u32,
    pub free_space_floor: ByteSize,
}

#[derive(Debug, Clone)]
pub struct Safety {
    pub active_window_minutes: u32,
    pub max_walk_depth: usize,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Projects {
    /// FR-25: **empty by default.** There is deliberately no "scan my whole home
    /// directory for `target/`" behaviour; S6 and S11 find nothing until the
    /// user names their project roots.
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Schedule {
    pub hour: u32,
    pub minute: u32,
    pub skip_on_battery_below: u8,
    pub notify_threshold: ByteSize,
    pub max_days_between_runs: u32,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub id: String,
    pub enabled: bool,
    pub min_age_days: Option<u32>,
    pub risk: Risk,
    pub urgency: Option<u8>,
    pub autoremove: Option<bool>,
    pub prefer_delegation: Option<bool>,
}

/// Where an effective value came from (FR-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    Default,
    File,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Default => "default",
            Provenance::File => "file",
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
    /// Load from the default location. A missing file means all defaults
    /// (FR-22) and is not an error.
    pub fn load() -> Result<Self> {
        let path = paths::config_file()?;
        if path.exists() {
            Self::load_from(&path)
        } else {
            Self::from_raw(RawConfig::default(), None)
        }
    }

    /// Load from an explicit path. Here a missing file *is* an error: the user
    /// named it, so silently substituting defaults would be dishonest.
    pub fn load_from(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| SiftError::Config(format!("cannot read {}: {e}", path.display())))?;
        let raw: RawConfig = toml::from_str(&text)
            .map_err(|e| SiftError::Config(format!("{}: {e}", path.display())))?;
        Self::from_raw(raw, Some(path.to_path_buf()))
    }

    /// Parse from a string, for tests and `--config -`.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| SiftError::Config(e.to_string()))?;
        Self::from_raw(raw, None)
    }

    fn from_raw(raw: RawConfig, source: Option<PathBuf>) -> Result<Self> {
        let g = raw.general.as_ref();
        let max_risk = match g.and_then(|g| g.max_risk.as_deref()) {
            Some(s) => s.parse::<Risk>().map_err(SiftError::Config)?,
            None => defaults::MAX_RISK,
        };

        let general = General {
            max_risk,
            max_bytes_per_run: g
                .and_then(|g| g.max_bytes_per_run)
                .unwrap_or(defaults::MAX_BYTES_PER_RUN),
            quarantine_ttl_days: g
                .and_then(|g| g.quarantine_ttl_days)
                .unwrap_or(defaults::QUARANTINE_TTL_DAYS),
            free_space_floor: g
                .and_then(|g| g.free_space_floor)
                .unwrap_or(defaults::FREE_SPACE_FLOOR),
        };

        let s = raw.safety.as_ref();
        let safety = Safety {
            active_window_minutes: s
                .and_then(|s| s.active_window_minutes)
                .unwrap_or(defaults::ACTIVE_WINDOW_MINUTES),
            max_walk_depth: s
                .and_then(|s| s.max_walk_depth)
                .unwrap_or(defaults::MAX_WALK_DEPTH),
            exclude: s.and_then(|s| s.exclude.clone()).unwrap_or_default(),
        };

        let roots = match raw.projects.as_ref().and_then(|p| p.roots.clone()) {
            Some(list) => list.iter().map(paths::expand).collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        let projects = Projects { roots };

        let sc = raw.schedule.as_ref();
        let schedule = Schedule {
            hour: sc.and_then(|s| s.hour).unwrap_or(defaults::SCHEDULE_HOUR),
            minute: sc
                .and_then(|s| s.minute)
                .unwrap_or(defaults::SCHEDULE_MINUTE),
            skip_on_battery_below: sc
                .and_then(|s| s.skip_on_battery_below)
                .unwrap_or(defaults::SKIP_ON_BATTERY_BELOW),
            notify_threshold: sc
                .and_then(|s| s.notify_threshold)
                .unwrap_or(defaults::NOTIFY_THRESHOLD),
            max_days_between_runs: sc
                .and_then(|s| s.max_days_between_runs)
                .unwrap_or(defaults::MAX_DAYS_BETWEEN_RUNS),
        };

        let mut scanners = BTreeMap::new();
        for d in defaults::SCANNERS {
            let user = raw.scanners.as_ref().and_then(|m| m.get(d.id));
            scanners.insert(
                d.id.to_string(),
                ScannerConfig {
                    id: d.id.to_string(),
                    enabled: user.and_then(|u| u.enabled).unwrap_or(d.enabled),
                    min_age_days: user.and_then(|u| u.min_age_days).or(d.min_age_days),
                    risk: d.risk,
                    urgency: user.and_then(|u| u.urgency),
                    autoremove: user.and_then(|u| u.autoremove),
                    prefer_delegation: user.and_then(|u| u.prefer_delegation),
                },
            );
        }

        let cfg = Config {
            general,
            safety,
            projects,
            schedule,
            scanners,
            source,
            raw,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    fn validate(&self) -> Result<()> {
        if let Some(map) = &self.raw.scanners {
            for (id, raw) in map {
                let Some(def) = defaults::scanner(id) else {
                    let mut known = defaults::scanner_ids();
                    known.sort_unstable();
                    return Err(SiftError::Config(format!(
                        "scanners.{id}: unknown scanner. Known scanners: {}",
                        known.join(", ")
                    )));
                };

                // A scanner-specific key on the wrong scanner is an error. It
                // would otherwise parse fine and do nothing, which is precisely
                // the silent misconfiguration deny_unknown_fields exists to stop.
                let check = |present: bool, key: &str| -> Result<()> {
                    if present && !def.extra_keys.contains(&key) {
                        return Err(SiftError::Config(format!(
                            "scanners.{id}: `{key}` is not a valid key for this scanner"
                        )));
                    }
                    Ok(())
                };
                check(raw.urgency.is_some(), "urgency")?;
                check(raw.autoremove.is_some(), "autoremove")?;
                check(raw.prefer_delegation.is_some(), "prefer_delegation")?;

                if let Some(u) = raw.urgency {
                    if !(1..=4).contains(&u) {
                        return Err(SiftError::Config(format!(
                            "scanners.{id}: urgency must be 1..=4, got {u} (spec §6 S1)"
                        )));
                    }
                }
            }
        }

        let sched = &self.schedule;
        if sched.hour > 23 {
            return Err(SiftError::Config(format!(
                "schedule.hour must be 0..=23, got {}",
                sched.hour
            )));
        }
        if sched.minute > 59 {
            return Err(SiftError::Config(format!(
                "schedule.minute must be 0..=59, got {}",
                sched.minute
            )));
        }
        if sched.skip_on_battery_below > 100 {
            return Err(SiftError::Config(format!(
                "schedule.skip_on_battery_below must be 0..=100, got {}",
                sched.skip_on_battery_below
            )));
        }

        if self.general.quarantine_ttl_days == 0 {
            return Err(SiftError::Config(
                "general.quarantine_ttl_days must be at least 1; a zero TTL would purge \
                 quarantine on the same run that created it, defeating FR-6's reversibility \
                 window"
                    .into(),
            ));
        }

        if self.general.max_bytes_per_run.bytes() == 0 {
            return Err(SiftError::Config(
                "general.max_bytes_per_run must be greater than zero".into(),
            ));
        }

        if self.safety.max_walk_depth == 0 {
            return Err(SiftError::Config(
                "safety.max_walk_depth must be at least 1".into(),
            ));
        }

        // Validate exclude globs eagerly so a malformed pattern is a config
        // error at load, not a surprise mid-run (FR-24).
        for pat in &self.safety.exclude {
            let expanded = paths::expand(pat)?;
            globset::Glob::new(&expanded.to_string_lossy()).map_err(|e| {
                SiftError::Config(format!("safety.exclude: invalid glob `{pat}`: {e}"))
            })?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Build the compiled exclude set (FR-24).
    pub fn exclude_globs(&self) -> Result<globset::GlobSet> {
        let mut b = globset::GlobSetBuilder::new();
        for pat in &self.safety.exclude {
            let expanded = paths::expand(pat)?;
            let glob = globset::Glob::new(&expanded.to_string_lossy()).map_err(|e| {
                SiftError::Config(format!("safety.exclude: invalid glob `{pat}`: {e}"))
            })?;
            b.add(glob);
        }
        b.build()
            .map_err(|e| SiftError::Config(format!("safety.exclude: {e}")))
    }

    pub fn scanner(&self, id: &str) -> Option<&ScannerConfig> {
        self.scanners.get(id)
    }

    /// Scanners that are enabled *and* whose risk tier the config admits.
    ///
    /// Both conditions are required (PR-36's two-switch arming model): enabling
    /// a Destructive scanner is not sufficient if `max_risk` does not reach it.
    pub fn active_scanners(&self) -> Vec<&ScannerConfig> {
        self.scanners
            .values()
            .filter(|s| s.enabled && s.risk <= self.general.max_risk)
            .collect()
    }

    /// Provenance of each effective value, for `sift config check` (FR-23).
    pub fn provenance(&self) -> Vec<(String, String, Provenance)> {
        let mut out = Vec::new();
        let g = self.raw.general.as_ref();
        let s = self.raw.safety.as_ref();
        let sc = self.raw.schedule.as_ref();

        let mut push = |key: &str, value: String, from_file: bool| {
            out.push((
                key.to_string(),
                value,
                if from_file {
                    Provenance::File
                } else {
                    Provenance::Default
                },
            ));
        };

        push(
            "general.max_risk",
            self.general.max_risk.to_string(),
            g.map(|g| g.max_risk.is_some()).unwrap_or(false),
        );
        push(
            "general.max_bytes_per_run",
            self.general.max_bytes_per_run.to_string(),
            g.map(|g| g.max_bytes_per_run.is_some()).unwrap_or(false),
        );
        push(
            "general.quarantine_ttl_days",
            self.general.quarantine_ttl_days.to_string(),
            g.map(|g| g.quarantine_ttl_days.is_some()).unwrap_or(false),
        );
        push(
            "general.free_space_floor",
            self.general.free_space_floor.to_string(),
            g.map(|g| g.free_space_floor.is_some()).unwrap_or(false),
        );
        push(
            "safety.active_window_minutes",
            self.safety.active_window_minutes.to_string(),
            s.map(|s| s.active_window_minutes.is_some())
                .unwrap_or(false),
        );
        push(
            "safety.max_walk_depth",
            self.safety.max_walk_depth.to_string(),
            s.map(|s| s.max_walk_depth.is_some()).unwrap_or(false),
        );
        push(
            "safety.exclude",
            format!("{} pattern(s)", self.safety.exclude.len()),
            s.map(|s| s.exclude.is_some()).unwrap_or(false),
        );
        push(
            "projects.roots",
            format!("{} root(s)", self.projects.roots.len()),
            self.raw
                .projects
                .as_ref()
                .map(|p| p.roots.is_some())
                .unwrap_or(false),
        );
        push(
            "schedule.hour",
            self.schedule.hour.to_string(),
            sc.map(|s| s.hour.is_some()).unwrap_or(false),
        );
        push(
            "schedule.minute",
            self.schedule.minute.to_string(),
            sc.map(|s| s.minute.is_some()).unwrap_or(false),
        );
        push(
            "schedule.skip_on_battery_below",
            format!("{}%", self.schedule.skip_on_battery_below),
            sc.map(|s| s.skip_on_battery_below.is_some())
                .unwrap_or(false),
        );
        push(
            "schedule.notify_threshold",
            self.schedule.notify_threshold.to_string(),
            sc.map(|s| s.notify_threshold.is_some()).unwrap_or(false),
        );
        push(
            "schedule.max_days_between_runs",
            self.schedule.max_days_between_runs.to_string(),
            sc.map(|s| s.max_days_between_runs.is_some())
                .unwrap_or(false),
        );

        for (id, cfg) in &self.scanners {
            let user = self.raw.scanners.as_ref().and_then(|m| m.get(id));
            push(
                &format!("scanners.{id}.enabled"),
                cfg.enabled.to_string(),
                user.map(|u| u.enabled.is_some()).unwrap_or(false),
            );
            if let Some(age) = cfg.min_age_days {
                push(
                    &format!("scanners.{id}.min_age_days"),
                    age.to_string(),
                    user.map(|u| u.min_age_days.is_some()).unwrap_or(false),
                );
            }
        }

        out
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_raw(RawConfig::default(), None).expect("built-in defaults must be valid")
    }
}
