# Configuration

`~/.config/sift/config.toml`. Every key is optional, and **the absence of the
file means all defaults** — which are conservative: every destructive scanner is
off.

`sift config check` prints the effective merged configuration and marks which
values you set:

```
  general.max_risk                rebuildable
  general.quarantine_ttl_days     3             [set in file]
```

**Unknown keys are errors, not warnings.** A typo like `min_age_day` silently
falling back to a default is exactly the quiet failure that gets data deleted.

## A complete example

```toml
[general]
# safe | rebuildable | destructive
max_risk             = "rebuildable"
# Abort before acting if the total exceeds this (FR-16).
max_bytes_per_run    = "100GiB"
# How long quarantined items stay recoverable.
quarantine_ttl_days  = 7
# Scheduled runs skip when free space is above this.
free_space_floor     = "100GiB"

[safety]
# Refuse any tree with something modified this recently.
active_window_minutes = 60
# Final veto over every scanner.
exclude = [
  "~/dev/active-client/**",
  "**/*.keychain-db",
]

[projects]
# Required for rust-targets and python-caches. Empty by default —
# there is deliberately no "search my whole home directory" mode.
roots = ["~/dev", "~/src"]

[schedule]
hour                  = 3
minute                = 0
skip_on_battery_below = 30
notify_threshold      = "1GiB"
# Overrides free_space_floor once runs have not happened for this long,
# so work stays incremental instead of accumulating.
max_days_between_runs = 14

[scanners.xcode-derived]
enabled      = true
min_age_days = 14

[scanners.snapshots]
enabled = false
urgency = 1          # 1..=4, least aggressive first

[scanners.homebrew]
autoremove = false   # can uninstall things you wanted

[scanners.rust-targets]
prefer_delegation = true   # false forces the native, undoable path
```

## Byte sizes

`"100GiB"`, `"1GB"`, `1024`. **SI and binary units mean different things** —
`GB` is 1000³ and `GiB` is 1024³ — because conflating them would make the
circuit-breaker limit 7% larger than what you wrote.

## Per-scanner keys

Every scanner accepts `enabled` and (where age applies) `min_age_days`. Three
accept more:

| Key | Scanner | Meaning |
|---|---|---|
| `urgency` | `snapshots` | 1–4. macOS declines at low urgency if thinning would compromise recovery. |
| `autoremove` | `homebrew` | Also run `brew autoremove`. Off by default: it can uninstall a package you installed deliberately. |
| `prefer_delegation` | `rust-targets`, `cargo-cache` | Use `cargo-sweep` / `cargo-cache` when installed. Delegation **bypasses quarantine**, so `false` forces the undoable native path. |

Using one of these on the wrong scanner is an error, not a silent no-op.

## Arming a destructive scanner

Two switches, both required:

```toml
[general]
max_risk = "destructive"

[scanners.trash]
enabled = true
```

Either alone does nothing. `sift config check` tells you when you have only one:

```
note: 1 enabled but inactive because max_risk = rebuildable does not
      admit their risk tier:
        trash (destructive)
      raise general.max_risk to activate them.
```

Interactively you will also be asked to type the scanner's name. See
[safety.md](safety.md).

## Paths

| | |
|---|---|
| config | `~/.config/sift/config.toml` (or `$XDG_CONFIG_HOME/sift/`) |
| quarantine | `~/.local/state/sift/quarantine/` |
| history | `~/.local/state/sift/history.jsonl` |
| agent logs | `~/.local/state/sift/agent.{out,err}.log` |
| LaunchAgent | `~/Library/LaunchAgents/com.cindral.sift.plist` |

`sift uninstall` removes all of these **except the history**, whose path it
prints for you to delete yourself. It is the only record of what sift ever did.
