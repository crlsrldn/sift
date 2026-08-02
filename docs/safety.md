# How sift decides what to delete

This document exists because the commercial cleaner market trades on the
opposite — opaque heuristics, a "smart scan" button, and no way to find out what
happened. If you are going to give a program permission to delete things, you
should be able to read how it decides.

## The one rule everything else follows

**Allowlist, never blocklist.**

A path is a deletion candidate only because a specific scanner claimed it by an
explicit rule. There is no mode that scans your disk and excludes the parts it
thinks are dangerous, and there is no plan to add one. That design is what makes
the question "could sift delete this?" answerable — run `sift explain <path>`
and find out.

Every scanner's rules are in [scanners.md](scanners.md).

## What happens to something sift claims

```
scan  →  filter  →  liveness  →  circuit breaker  →  confirm  →  quarantine  →  purge
```

**Nothing is deleted at scan time.** `sift` with no arguments reports.

**Deletion is staged, not immediate.** `sift clean` moves candidates into
`~/.local/state/sift/quarantine/<run-id>/` by `rename(2)` — an inode operation
that costs zero additional bytes and is instant. They are hard-deleted only
after the TTL expires, by default seven days later.

**The undo is printed every time.**

```
Quarantined 1 item(s), 1.7 GB.
  Undo:    sift restore 019fbea3
  Expires: in 7 days, after which it is purged automatically.
```

**Restore refuses rather than overwrites.** If you rebuilt the thing in the
meantime, restore reports a conflict and leaves both copies alone. A partial
restore is a normal outcome, and re-running retries only what is left.

## The guards, and what each is for

| Guard | Prevents |
|---|---|
| **Minimum age** | Nothing younger than its scanner's floor is eligible, regardless of size. |
| **Liveness window** | A tree with *anything* modified in the last hour is refused. A directory's own mtime does not change when a file three levels down is rewritten, so the check walks the tree — this is what stops sift quarantining a running build. |
| **Circuit breaker** | If the total exceeds `max_bytes_per_run` (100 GiB default) the run aborts **before acting on anything** and names the scanner responsible. A scanner bug should not stage your whole disk. |
| **Device check** | The walk never crosses onto another volume, disk image, or network share. |
| **Firmlink guard** | `/System/Volumes/Data` is firmlinked into `/`; without this every file would be counted twice. |
| **No symlink following** | Cycles are unreachable rather than merely bounded, and a link is never counted as its target. |
| **Dataless check** | iCloud-evicted files are skipped and never actioned. Reading one downloads it. |
| **Excludes** | Your `safety.exclude` globs are the final veto over everything else. |

## The destructive tier

Five scanners can destroy something you cannot get back. Three independent
things stand between them and your data:

1. `enabled = true` for that scanner
2. `max_risk = "destructive"`
3. typing the scanner's **name** at an interactive prompt

**`--yes` satisfies none of them.** Scripting `sift clean --yes` in a cron job
does not consent to emptying your Trash. `y` does not confirm a destructive
scanner — `[y/N]` is a reflex people answer while reading something else.

Before asking, sift states what you lose:

```
  trash — 4.2 GB across 12 item(s)

    Everything listed is permanently erased. Not moved, not staged —
    erased. `sift restore` cannot bring it back, Finder's Put Back
    cannot, and no undo exists.

  This bypasses quarantine. `sift restore` CANNOT undo it.

  Type `trash` to confirm, anything else to skip:
```

## What sift will never do

- **Run as root.** No privileged helper, no daemon. This removes the entire
  attack surface that defines the incumbent products.
- **Touch the network.** Zero outbound connections, enforced in CI by a
  dependency audit that fails the build if any HTTP or TLS crate appears in the
  shipped graph.
- **Send telemetry.** There is nowhere for it to go.
- **Delete iCloud content.** Evicted files are skipped even during a size walk.
- **Touch `/System`.** SIP makes it impossible and it is not worth discussing.

## Things sift is honest about being bad at

**APFS clones make sizes overcount.** `cp -c`, Finder copies, and Xcode create
files that share blocks but each report their full size. A tree containing
clones reports more than you will actually reclaim. Sizes are estimates; the
free-space delta across a purge is the ground truth, and that is what the
history records.

**The liveness guard is a heuristic.** It catches a build actively writing. It
does **not** catch a process holding a file open without writing, or one about
to start. The quarantine window is what covers the rest, not this check.

**Quarantine frees nothing immediately.** It is a same-volume rename, so the
bytes are still on disk until the TTL expires and they are purged. `df` will not
move until then. That is the cost of being able to undo.

**Delegated commands cannot be undone.** `brew cleanup`, `docker prune`, and
`simctl delete unavailable` are run by their own tools, which do not stage
anything. Every such candidate says so in its reason string.

## The tests that keep this true

Four gates run on every change:

| Gate | What it asserts |
|---|---|
| `never_touch.rs` | A corpus of SSH keys, GPG keyrings, the macOS keychain, AWS credentials, documents, photos, source code, `.git`, toolchains, and browser cookies yields **zero candidates** with every scanner enabled at `max_risk = "destructive"`. |
| `property_containment.rs` | Over randomly generated trees and configurations, every actioned path lies inside a declared allowlist root. |
| `roundtrip.rs` | `clean` → `restore` is byte-identical, including file modes. |
| `audit-deps.sh` | No network or TLS crate reaches the binary. |

They are checked by deliberately breaking a scanner and confirming they fail —
a gate that cannot fail is worse than no gate. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
