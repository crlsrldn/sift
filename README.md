# sift

**An automated, safety-first disk reclamation agent for macOS.**

macOS reports a large, opaque "System Data" bucket in *Settings → General →
Storage* with no drill-down and no remedy. On a developer's machine it is
usually Xcode DerivedData, iOS DeviceSupport bundles, Rust `target/`
directories, container images, and package-manager caches — individually
invisible, collectively enormous.

`sift` finds that space, tells you what it is in terms you recognise, and
reclaims it on a schedule. Locally, without root, without telemetry, and
reversibly.

```
sift — scan complete in 0.4s
Volume: Macintosh HD  ·  32.2 GB free of 245.1 GB

  Xcode                                                    31.7 GB
    iOS DeviceSupport   iOS 15.x–16.x, 9 bundles           22.1 GB   rebuildable
    DerivedData         14 projects, >14d idle              8.4 GB   rebuildable
    Simulator caches                                        1.2 GB   safe
  Rust                                                      9.3 GB
    target/  6 projects under ~/dev, >30d idle              8.8 GB   rebuildable

  Total identified                                         41.0 GB

  Skipped: snapshots, trash (disabled)
  Blocked: mail-downloads — needs Full Disk Access (run `sift doctor`)

Run `sift clean` to quarantine. Nothing has been deleted.
```

<sub>Illustrative — a well-used developer machine, not a capture from any
particular one. The layout is exact; the numbers are what this is *for*.</sub>

> **Status: pre-release.** Not yet signed or notarized, and not yet on a
> Homebrew tap. Build from source.
>
> Every scanner but one has now been run against real data on macOS 26 with
> Xcode 26.6. The exception is `xcode-devicesupport`, which needs a physical
> iPhone attached before its directories exist at all — see
> [docs/scanners.md](docs/scanners.md).

## Install

```bash
git clone https://github.com/crlsrldn/sift && cd sift
cargo build --release
cp target/release/sift ~/.local/bin/sift    # copy, not symlink — see below
```

**Copy rather than symlink.** `sift install` records the binary's *canonical*
path in the LaunchAgent, so installing through a symlink would point launchd at
`target/release/sift` — and `cargo clean` would then break your scheduled run
silently. `sift install` refuses to schedule a build artifact for this reason.

**Checking what you have.** Since there are no releases yet, the crate version
alone cannot tell you which build you are running, so `--version` carries the
commit:

```
$ sift --version
sift 0.1.0 (d6c302d, built 2026-08-02)
```

A `-dirty` suffix means the tree had uncommitted changes when it was built.
Builds honour `SOURCE_DATE_EPOCH`, so the same source produces a byte-identical
binary.

## Use

```bash
sift                       # report. deletes nothing.
sift doctor                # permissions, tools, per-scanner status
sift explain ~/Library/Caches   # what is this, and would sift touch it?

sift clean --dry-run       # exactly what would happen, and nothing else
sift clean                 # quarantine, with confirmation
sift restore <run-id>      # undo
sift purge                 # hard-delete quarantined items past their TTL

sift install --dry-run     # the plist and launchctl command, unexecuted
sift install               # daily at 03:00, low priority
sift report                # history and trend
```

`--json` works on every command, and `--only <glob>` narrows `scan` and `clean`
to matching scanners (`sift scan --only 'xcode-*'`).

**`--estimate-delegated`.** Four scanners hand the work to the tool that owns
it — `brew`, `docker`, `npm`, `simctl`. A plain `scan` never asks those tools
anything, because it is not allowed to spawn subprocesses, so their lines read
`unknown` rather than a number. Pass `--estimate-delegated` to `scan` or
`clean` and sift asks each one what it would free:

```bash
sift scan --estimate-delegated
```

It costs a few seconds and lets those tools create their own cache
directories, which is why it is not the default.

**`--include-disabled`.** `enabled = false` was doing two unrelated jobs:
*never act on this*, which is why people set it, and *never tell me about
this*, which nobody chose. Disabling the delegated scanners to keep a nightly
run reversible should not also cost you the ability to see what they hold:

```bash
sift scan --include-disabled
```

Switched-off scanners are reported in their own block, with their own total,
excluded from `Total identified` — and `clean` still ignores them entirely.
`scan` never acts, so looking is free. The flag exists on `scan` alone; there
is no argument that turns a disabled scanner into a deletion.

It overrides the `enabled` switch only. A scanner above your `max_risk`
ceiling stays unrun and says so, because that is a separate decision.

## What it will not do

- **Run as root.** No privileged helper, no daemon.
- **Touch the network.** Enforced in CI by a dependency audit that fails the
  build if any HTTP or TLS crate reaches the binary.
- **Delete anything you did not ask about.** A path is a candidate only because
  a scanner claimed it by an explicit rule. There is no "scan everything and
  exclude the dangerous bits" mode.
- **Delete anything irreversibly without saying so first**, and for the five
  destructive scanners, without two config switches *and* you typing the
  scanner's name.

Everything is staged by `rename(2)` into a quarantine on the same volume — zero
additional bytes — and hard-deleted only after a TTL, by default seven days.

## `sift explain`

The most direct answer to "what is all this?":

```
$ sift explain '~/Library/Mobile Documents'
/Users/you/Library/Mobile Documents

  size        40.7 GB
  what        iCloud Drive. Everything in your iCloud Drive and any app that
              syncs through it — Desktop and Documents too, if you enabled that.

  if deleted  Deleting from here deletes it from iCloud, and therefore from
              every device signed into your account.

  VERDICT     No scanner claims this, under any configuration.
              sift will never delete it. If it is large and you
              want it gone, that is a decision only you can make.
```

## Documentation

| | |
|---|---|
| [docs/scanners.md](docs/scanners.md) | All 17 scanners: what each targets, how it decides, what you lose |
| [docs/safety.md](docs/safety.md) | How deletion decisions are made, and what sift is bad at |
| [docs/config.md](docs/config.md) | Annotated configuration reference |
| [docs/verifying-fda.md](docs/verifying-fda.md) | Checking the Full Disk Access path by hand |
| [CONTRIBUTING.md](CONTRIBUTING.md) | The fixture-before-fix rule, and why a green test can be worthless |

## Full Disk Access

Four scanners need it. Grant it to **the sift binary itself**, not to Terminal:

```
System Settings → Privacy & Security → Full Disk Access → +  →  ⌘⇧G
~/.local/bin/sift
```

FDA granted to Terminal covers interactive runs and does nothing for the
scheduled agent, because launchd is that process's parent. `sift doctor`
detects that specific mismatch and says so.

## How this is tested

540 tests, and two rules that matter more than the number.

**A test that cannot fail is not a test.** Four separate safety tests in this
repo were green while proving nothing — a fixture collision meant a guard test
had never actually run, a containment check was skipping its own body, and the
never-touch corpus was silently omitting the three most dangerous scanners.
Every one was found by asking *"would this fail if the code were wrong?"*, not
by the test failing. New safety tests are sabotage-checked against a
deliberately broken implementation before they count.

**Fixtures drift from reality.** These scanners were built against invented
fixtures on a machine with no Xcode. The day a real Xcode went on and a real
build ran, two naming bugs surfaced in the first scan — one of them printing a
project that did not exist as the largest line in the report. Fixtures now use
observed shapes, and anything still unverified against real hardware says so in
[docs/scanners.md](docs/scanners.md).

[CONTRIBUTING.md](CONTRIBUTING.md) has the details.

## Requirements

macOS 13 Ventura or later · **Apple Silicon only** · APFS.

Developed and tested on macOS 26 with Xcode 26.6.

## License

MIT — see [LICENSE](LICENSE).
