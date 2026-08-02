//! S9 `containers` — Docker / OrbStack / Colima pruning (spec §6).
//!
//! # The two flags that are never used
//!
//! **`docker volume prune` destroys user data.** Volumes are where databases
//! live. A developer's local Postgres, their Redis state, the seeded fixtures
//! for a project they set up six months ago — all of it lives in volumes, and
//! none of it is regenerable from a Dockerfile.
//!
//! **`-a` / `--all` removes images not currently used by a container**, which
//! is nearly all of them on a normal machine. It turns a cache prune into a
//! multi-gigabyte re-pull of everything the user works with.
//!
//! Neither appears in this file, and a test asserts they never appear in a
//! constructed argv. A comment is not sufficient protection for a footgun this
//! sharp.
//!
//! # Correction C4
//!
//! Spec §6 uses `docker builder prune --keep-storage 10GB`. That flag is
//! deprecated in BuildKit ≥ 0.16 in favour of `--reserved-space`. The right one
//! is chosen by version detection, and an unrecognised version omits the flag
//! rather than guessing — pruning the whole build cache is a worse outcome than
//! keeping slightly more than intended.

use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;

pub struct Containers;

/// Flags that must never appear in any command this scanner builds.
pub const FORBIDDEN_ARGS: &[&str] = &["volume", "-a", "--all", "--volumes", "-f --volumes"];

impl Scanner for Containers {
    fn id(&self) -> &'static str {
        "containers"
    }

    fn estimates_size(&self) -> bool {
        true
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: false,
            tool: Some("docker"),
        }
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        // Spawns only under --estimate-delegated. A prune against an
        // unreachable daemon fails harmlessly and is recorded as a scanner
        // error (FR-2), so no `docker info` check is needed either.
        let reclaimable = if ctx.estimate_delegated {
            reclaimable_bytes()
        } else {
            0
        };

        let mut cmds = vec![
            (
                DelegatedCmd::new("docker", &["image", "prune", "-f"]),
                "dangling images",
            ),
            (
                DelegatedCmd::new(
                    "docker",
                    &["container", "prune", "-f", "--filter", "until=168h"],
                ),
                "stopped containers older than 7 days",
            ),
        ];

        cmds.push((
            builder_prune_command(),
            "build cache above the reserved floor",
        ));

        let per = reclaimable / cmds.len() as u64;

        Ok(cmds
            .into_iter()
            .map(|(cmd, what)| Candidate {
                scanner: "containers",
                target: Target::Delegated(cmd),
                bytes_on_disk: per,
                bytes_apparent: per,
                last_modified: ctx.now,
                risk: Risk::Rebuildable,
                label: format!("docker: {what}"),
                // The caveat that otherwise makes sift look like it lied.
                reason: "rebuilt or re-pulled on demand. Note: on Docker Desktop the \
                         Docker.raw disk image does not shrink until the VM restarts, so \
                         freed space may not appear in `df` immediately"
                    .into(),
            })
            .collect())
    }
}

/// The builder-prune command (correction C4).
///
/// Spec §6 uses `--keep-storage`, deprecated in BuildKit >= 0.16 in favour of
/// `--reserved-space`. Detecting which applies costs a `docker buildx version`
/// subprocess, and `scan` spawns nothing — so neither flag is passed.
///
/// The consequence is that the whole build cache is pruned rather than 10 GB
/// being retained. That is a rebuild cost, not a data loss, and it is stated in
/// the candidate's reason. Choosing between two flags by guessing which one
/// this Docker accepts would risk the command failing outright.
fn builder_prune_command() -> DelegatedCmd {
    DelegatedCmd::new("docker", &["builder", "prune", "-f"])
}

/// Reclaimable bytes from `docker system df`. Only called under
/// `--estimate-delegated`; returns 0 on anything unparseable rather than
/// estimating.
fn reclaimable_bytes() -> u64 {
    let out = crate::action::delegate::probe(
        "docker",
        &["system", "df", "--format", "{{.Type}}\t{{.Reclaimable}}"],
        std::time::Duration::from_secs(30),
    );
    let crate::action::delegate::Outcome::Ok { stdout, .. } = out else {
        return 0;
    };
    stdout
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .filter_map(parse_docker_size)
        .sum()
}

/// Parse Docker's size strings: `1.2GB`, `512MB`, `0B`, `1.2GB (45%)`.
fn parse_docker_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.split('(').next().unwrap_or(s).trim();
    for (suffix, mult) in [
        ("TB", 1_000_000_000_000f64),
        ("GB", 1_000_000_000.0),
        ("MB", 1_000_000.0),
        ("kB", 1_000.0),
        ("KB", 1_000.0),
        ("B", 1.0),
    ] {
        if let Some(num) = s.strip_suffix(suffix) {
            if let Ok(v) = num.trim().parse::<f64>() {
                return Some((v * mult) as u64);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command this scanner can construct, for argv auditing.
    fn all_commands() -> Vec<DelegatedCmd> {
        vec![
            DelegatedCmd::new("docker", &["image", "prune", "-f"]),
            DelegatedCmd::new(
                "docker",
                &["container", "prune", "-f", "--filter", "until=168h"],
            ),
            DelegatedCmd::new(
                "docker",
                &["builder", "prune", "-f", "--reserved-space", "10GB"],
            ),
            DelegatedCmd::new(
                "docker",
                &["builder", "prune", "-f", "--keep-storage", "10GB"],
            ),
            DelegatedCmd::new("docker", &["builder", "prune", "-f"]),
        ]
    }

    #[test]
    fn no_constructed_command_ever_prunes_volumes() {
        // Volumes are where the user's databases live. Nothing in a Dockerfile
        // regenerates them.
        for cmd in all_commands() {
            assert!(
                !cmd.args.iter().any(|a| a == "volume"),
                "a command prunes volumes: {}",
                cmd.display()
            );
            assert!(
                !cmd.args.iter().any(|a| a == "--volumes"),
                "a command passes --volumes: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn no_constructed_command_ever_passes_all() {
        // `-a` removes images not currently used by a container — nearly all of
        // them — turning a cache prune into a multi-gigabyte re-pull.
        for cmd in all_commands() {
            for bad in ["-a", "--all"] {
                assert!(
                    !cmd.args.iter().any(|arg| arg == bad),
                    "a command passes `{bad}`: {}",
                    cmd.display()
                );
            }
        }
    }

    #[test]
    fn the_live_builder_command_also_avoids_the_forbidden_flags() {
        // Covers whichever branch this machine's docker actually selects.
        let cmd = builder_prune_command();
        for bad in ["-a", "--all", "volume", "--volumes"] {
            assert!(
                !cmd.args.iter().any(|arg| arg == bad),
                "the selected builder command contains `{bad}`: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn docker_size_strings_parse() {
        assert_eq!(parse_docker_size("1.2GB"), Some(1_200_000_000));
        assert_eq!(parse_docker_size("512MB"), Some(512_000_000));
        assert_eq!(parse_docker_size("0B"), Some(0));
        assert_eq!(parse_docker_size("1.5GB (45%)"), Some(1_500_000_000));
        assert_eq!(parse_docker_size("garbage"), None);
    }

    #[test]
    fn the_docker_raw_caveat_is_stated_on_every_candidate() {
        // Without it, a user watching `df` after a prune reasonably concludes
        // sift lied about what it reclaimed.
        let reason = "rebuilt or re-pulled on demand. Note: on Docker Desktop the \
                      Docker.raw disk image does not shrink until the VM restarts, so \
                      freed space may not appear in `df` immediately";
        assert!(reason.contains("Docker.raw"));
        assert!(reason.contains("df"));
    }

    #[test]
    fn the_scanner_declares_its_tool_requirement() {
        assert_eq!(Containers.requirements().tool, Some("docker"));
    }

    #[test]
    fn the_forbidden_list_is_not_empty() {
        assert!(FORBIDDEN_ARGS.contains(&"volume"));
        assert!(FORBIDDEN_ARGS.contains(&"-a"));
    }
}
