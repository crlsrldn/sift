# Contributing to sift

`sift` deletes people's files. That single fact sets every rule below.

## The fixture-before-fix rule

**Every safety bug gets a regression fixture before it gets a fix.**

Not after. Before.

A fix written first is a fix nobody can prove works, and nobody can prove stays
working. Writing the reproduction first forces the bug to be understood well
enough to reproduce it — which is usually where the real cause turns up, and
often turns out not to be where the fix was about to go.

The workflow is in [`tests/regressions/mod.rs`](tests/regressions/mod.rs).
Start from `TEMPLATE.rs`. If your new test passes against the unfixed code, you
have not reproduced the bug yet; do not proceed to the fix.

Nothing is ever removed from `tests/regressions/`.

## What a test has to be worth

A test that cannot fail is worse than no test: it reports green while proving
nothing, and it stops anyone from looking harder.

Two real examples from this repository's history:

- Two disk-image fixtures derived their paths from the process id. Run in
  parallel they collided, so **one of the two device-guard tests had never
  actually run.** It was written to skip silently on failure, which hid it.
- A purge containment test replaced a quarantine directory with a symlink —
  which also removed the manifest, so the run was skipped entirely and **the
  rail under test was never reached.**

Both were found by asking "would this fail if the code were wrong?" rather than
by the test failing. Ask that question of every safety test you write.

Corollaries:

- **Prefer a loud failure to a silent skip.** If a fixture cannot be built,
  panic. An environment that cannot run the test should be a visible problem.
- **Assert the premise.** If a test depends on two paths being on different
  devices, assert that before asserting the behaviour.
- **Verify effects, not output.** `--dry-run` is tested with a filesystem
  snapshot taken before and after, not by checking that it printed "nothing was
  deleted".

## The safety gates

These run on every pull request and are not optional:

| Gate | What it protects |
|---|---|
| `tests/never_touch.rs` | Every scanner, fully enabled, at `max_risk = "destructive"`, claims nothing from a corpus of keys, documents, toolchains, and user state. |
| `tests/property_containment.rs` | Over random trees and random configs, every actioned path lies inside a declared allowlist root. |
| `tests/roundtrip.rs` | `clean` → `restore` is byte-identical, including file modes. |
| `scripts/audit-deps.sh` | No network or TLS crate reaches the shipped binary (G4). |

If a change makes one of these fail, the change is wrong until proven otherwise.
Do not adjust the gate to accommodate the change without saying so explicitly in
the pull request and explaining why the gate was wrong.

## Principles that are not negotiable

From the PRD, in descending order of how badly violating them ends:

1. **Allowlist, never blocklist.** A path is a candidate only because a scanner
   claimed it by an explicit rule. There is no "scan everything and exclude the
   dangerous bits" mode, and adding one is not a feature request.
2. **Dry-run is the default.** `sift` with no arguments reports.
3. **Quarantine, then purge.** Deletions are staged by rename and hard-deleted
   only after a TTL.
4. **Age-gate everything.** Nothing younger than its scanner's floor is
   eligible, regardless of size.
5. **Refuse rather than guess.** A scanner that cannot determine safety returns
   nothing and logs why.
6. **No root.** If something needs root, it is out of scope.

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
bash scripts/audit-deps.sh
```

Scripts must work under **bash 3.2** — that is what macOS and the CI runner
ship. `mapfile` and associative arrays are not available.
