# Scanners

Seventeen scanners, each with its own eligibility rules, minimum age, and risk
tier. Every one can be enabled or disabled independently.

**Risk tiers**

| Tier | Meaning |
|---|---|
| **Safe** | Regenerates automatically. No user-visible effect. |
| **Rebuildable** | Regenerates at a cost — time, bandwidth, or a rebuild. |
| **Destructive** | Not recoverable once purged. Requires two config switches *and* typing the scanner's name. |

| Scanner | Tier | Default | Min age | Targets |
|---|---|---|---|---|
| [`snapshots`](#snapshots) | Destructive | Off | 7 d | APFS local Time Machine snapshots |
| [`xcode-derived`](#xcode-derived) | Rebuildable | On | 14 d | `~/Library/Developer/Xcode/DerivedData/*` |
| [`xcode-devicesupport`](#xcode-devicesupport) | Rebuildable | On | 90 d | `~/Library/Developer/Xcode/{iOS,watchOS,tvOS,macOS} DeviceSupport/*` |
| [`xcode-archives`](#xcode-archives) | Destructive | Off | 180 d | `~/Library/Developer/Xcode/Archives/*` |
| [`simulators`](#simulators) | Rebuildable | On | — | `xcrun simctl delete unavailable`, `CoreSimulator/Caches` |
| [`rust-targets`](#rust-targets) | Rebuildable | On | 30 d | `target/` under configured project roots |
| [`cargo-cache`](#cargo-cache) | Safe | On | 60 d | `~/.cargo/registry/{cache,src}`, `~/.cargo/git/checkouts` |
| [`homebrew`](#homebrew) | Safe | On | — | `brew cleanup --prune=all` |
| [`containers`](#containers) | Rebuildable | On | — | `docker image/container/builder prune` |
| [`node-caches`](#node-caches) | Safe | On | 60 d | `~/.npm/_cacache`, `pnpm store prune`, `yarn cache clean` |
| [`python-caches`](#python-caches) | Safe | On | 60 d | `~/Library/Caches/pip`, `uv cache prune`, `__pycache__` under project roots |
| [`trash`](#trash) | Destructive | Off | 30 d | `~/.Trash`, `/Volumes/*/.Trashes/$UID` |
| [`downloads`](#downloads) | Destructive | Off | 90 d | `~/Downloads` — `.dmg`, `.pkg`, `.iso`, `.zip` only |
| [`app-caches`](#app-caches) | Safe | On | 30 d | `~/Library/Caches/<bundle-id>` from a curated allowlist |
| [`ios-backups`](#ios-backups) | Destructive | Off | 365 d | `~/Library/Application Support/MobileSync/Backup/*` |
| [`mail-downloads`](#mail-downloads) | Safe | On | 90 d | `~/Library/Containers/com.apple.mail/.../Mail Downloads` |
| [`logs`](#logs) | Safe | On | 30 d | `~/Library/Logs/**`, `.crash` / `.diag` reports |

Anything not listed here, sift does not touch. There is no "scan everything and
exclude the dangerous bits" mode, and adding one would be a spec violation
rather than a feature. Use `sift explain <path>` to ask about any specific path.

---

## `snapshots`

*S1 · Destructive tier · **off** by default · minimum age 7 d*

**Targets:** APFS local Time Machine snapshots

**What it is.** Snapshots Time Machine restores from when your backup disk is not attached, including Finder's "restore this file to yesterday".

**How it decides.** Thinned oldest-first via `tmutil thinlocalsnapshots`, which lets macOS decline if recovery would suffer. **Never** `deletelocalsnapshots`, never the newest snapshot, and never at all if fewer than two exist.

**What you lose.** Permanently. They are not on your backup drive.

## `xcode-derived`

*S2 · Rebuildable tier · on by default · minimum age 14 d*

**Targets:** `~/Library/Developer/Xcode/DerivedData/*`

**What it is.** Xcode build output: compiled objects, indexes, module caches. One directory per project.

**How it decides.** Claimed when the directory is idle past the floor **and** nothing anywhere inside was touched in the last hour. `ModuleCache.noindex` under 1 GB is preserved — it is shared and expensive to rebuild.

**What you lose.** A full rebuild of that project. Minutes, not data.

## `xcode-devicesupport`

*S3 · Rebuildable tier · on by default · minimum age 90 d*

**Targets:** `~/Library/Developer/Xcode/{iOS,watchOS,tvOS,macOS} DeviceSupport/*`

**What it is.** Symbol files Xcode downloads the first time you attach a device on a given OS version. Usually the largest single item on a developer's machine.

**How it decides.** Eligible only when at least **two major versions** behind the newest present. The newest bundle is never touched. Directory names that do not parse as a version are skipped rather than guessed at.

**What you lose.** Re-downloaded automatically on next device connect.

## `xcode-archives`

*S4 · Destructive tier · **off** by default · minimum age 180 d*

**Targets:** `~/Library/Developer/Xcode/Archives/*`

**What it is.** Builds you distributed, including the dSYMs that turn crash addresses into function names.

**How it decides.** Requires both config switches and typing `xcode-archives` at a prompt.

**What you lose.** **Crash reports from those released builds become unreadable, permanently.** Apple keeps no copy.

## `simulators`

*S5 · Rebuildable tier · on by default · minimum age —*

**Targets:** `xcrun simctl delete unavailable`, `CoreSimulator/Caches`

**What it is.** Simulator devices for runtimes you no longer have installed, and the dyld caches.

**How it decides.** Devices are removed **only** through `simctl`. `CoreSimulator/Devices` is a hard deny — `simctl` keeps an index beside it and deleting by hand corrupts it.

**What you lose.** Simulators are recreated on demand.

## `rust-targets`

*S6 · Rebuildable tier · on by default · minimum age 30 d*

**Targets:** `target/` under configured project roots

**What it is.** Cargo build output.

**How it decides.** Searches **only** `projects.roots`, which is empty by default — an unconfigured install finds nothing. A directory named `target` is claimed only if its **parent** contains `Cargo.toml`. Delegates to `cargo-sweep` when installed.

**What you lose.** A rebuild. Note that `cargo-sweep` delegation bypasses quarantine; set `prefer_delegation = false` for the undoable path.

## `cargo-cache`

*S7 · Safe tier · on by default · minimum age 60 d*

**Targets:** `~/.cargo/registry/{cache,src}`, `~/.cargo/git/checkouts`

**What it is.** Downloaded and unpacked crate sources.

**How it decides.** Exactly those three paths. `~/.cargo/bin` and `~/.rustup` are hard denies with their own tests.

**What you lose.** Re-fetched or re-extracted on the next build.

## `homebrew`

*S8 · Safe tier · on by default · minimum age —*

**Targets:** `brew cleanup --prune=all`

**What it is.** Stale downloads and superseded versions in Homebrew's cache.

**How it decides.** Delegated. `brew autoremove` is opt-in and off by default — it can uninstall something you installed deliberately.

**What you lose.** Re-downloaded on next install.

## `containers`

*S9 · Rebuildable tier · on by default · minimum age —*

**Targets:** `docker image/container/builder prune`

**What it is.** Dangling images, stopped containers older than 7 days, and the build cache.

**How it decides.** **Never `docker volume prune`** — volumes are where your databases live. **Never `-a`** — that removes images not currently in use, which is nearly all of them. Both are asserted absent from every constructed command.

**What you lose.** Re-pulled or rebuilt. On Docker Desktop the `Docker.raw` image does not shrink until the VM restarts, so `df` may not move immediately.

## `node-caches`

*S10 · Safe tier · on by default · minimum age 60 d*

**Targets:** `~/.npm/_cacache`, `pnpm store prune`, `yarn cache clean`

**What it is.** Package-manager caches.

**How it decides.** `node_modules` is **never** claimed at any depth. It is not a cache — it is a project's installed tree, and the reinstall may not reproduce it.

**What you lose.** Re-fetched on next install.

## `python-caches`

*S11 · Safe tier · on by default · minimum age 60 d*

**Targets:** `~/Library/Caches/pip`, `uv cache prune`, `__pycache__` under project roots

**What it is.** Wheel caches and compiled bytecode.

**How it decides.** Virtualenvs (`.venv`, `venv`, `.tox`, …) are **never** claimed or descended into. `__pycache__` is searched only under configured project roots.

**What you lose.** Re-downloaded or regenerated on next import.

## `trash`

*S12 · Destructive tier · **off** by default · minimum age 30 d*

**Targets:** `~/.Trash`, `/Volumes/*/.Trashes/$UID`

**What it is.** Files you already asked macOS to delete.

**How it decides.** **Hard-deletes — this is the one action with no undo anywhere.** `~/.Trash` is already a quarantine, so staging into a second one buys nothing. Per-volume trash is scoped to your `$UID`. Requires Full Disk Access.

**What you lose.** **Gone. `sift restore` cannot help, and neither can Finder's Put Back.**

## `downloads`

*S13 · Destructive tier · **off** by default · minimum age 90 d*

**Targets:** `~/Downloads` — `.dmg`, `.pkg`, `.iso`, `.zip` only

**What it is.** Stale installers and archives.

**How it decides.** The extension list is exhaustive. A document, image, or video in Downloads is **never** eligible at any age or size.

**What you lose.** Re-downloadable. Despite the tier these go through quarantine, so `sift restore` works until the TTL expires.

## `app-caches`

*S14 · Safe tier · on by default · minimum age 30 d*

**Targets:** `~/Library/Caches/<bundle-id>` from a curated allowlist

**What it is.** Per-application caches.

**How it decides.** Driven entirely by `resources/app_cache_allowlist.toml`. **An unlisted bundle ID is never touched regardless of size.** No entry may name cookies, Local Storage, IndexedDB, or profile data — that is user state, not cache.

**What you lose.** Varies by app, from nothing to a slow first launch. Every allowlist entry states its own cost.

## `ios-backups`

*S15 · Destructive tier · **off** by default · minimum age 365 d*

**Targets:** `~/Library/Application Support/MobileSync/Backup/*`

**What it is.** iPhone and iPad backups.

**How it decides.** Named by device and date from the backup's own `Info.plist`. A backup whose plist cannot be read is skipped rather than offered as "some device backup". Requires Full Disk Access.

**What you lose.** **The only copy of anything not in iCloud** — app data, Health records, Messages attachments. Deleting a backup does not affect the device.

## `mail-downloads`

*S16 · Safe tier · on by default · minimum age 90 d*

**Targets:** `~/Library/Containers/com.apple.mail/.../Mail Downloads`

**What it is.** Attachments Mail saved while you viewed them.

**How it decides.** Requires Full Disk Access — the container is TCC-protected.

**What you lose.** Re-downloaded from the server when you open the message again.

## `logs`

*S17 · Safe tier · on by default · minimum age 30 d*

**Targets:** `~/Library/Logs/**`, `.crash` / `.diag` reports

**What it is.** Application logs and crash reports.

**How it decides.** `~/Library/Logs` only. `/var/log` and `/Library/Logs` are system-owned and permanently out of scope.

**What you lose.** Diagnostic history. Nothing an application needs to run.
