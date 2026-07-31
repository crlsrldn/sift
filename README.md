# sift

**An automated, safety-first disk reclamation agent for macOS.**

macOS reports a large, opaque "System Data" bucket with no drill-down and no
remedy. On a developer machine it is usually Xcode DerivedData, iOS DeviceSupport
bundles, Rust `target/` directories, container images, and package-manager caches
— individually invisible, collectively enormous.

`sift` finds that space, tells you what it is in terms you recognize, and reclaims
it on a schedule. Locally, without root, without telemetry, and reversibly.

> **Status: pre-alpha.** This is the PR-01 scaffold. No scanning or deletion
> capability is implemented yet. Do not install this expecting it to do anything.

## Design commitments

These are load-bearing, not aspirational. Each is enforced by tests.

- **Allowlist, never blocklist.** A path is a deletion candidate only if a specific
  scanner claims it by an explicit rule. There is no "scan everything and exclude
  the dangerous bits" mode.
- **Dry-run is the default.** `sift` with no arguments reports. It does not delete.
- **Quarantine, then purge.** Deletions are staged by rename to a same-volume
  quarantine directory — instant, zero additional bytes — and hard-deleted only
  after a TTL. You get a window to notice a mistake, and `sift restore` to undo it.
- **Age-gate everything.** Nothing younger than its scanner's minimum age is ever
  eligible, regardless of size.
- **Delegate to the owner tool.** `brew cleanup`, `docker prune`, and
  `simctl delete unavailable` know their own invariants better than we do.
- **No root, ever.** No privileged helper, no daemon. This eliminates the attack
  surface that defines the commercial cleaner products.
- **No network.** Zero outbound connections, enforced in CI by a dependency audit
  that fails the build if any transitive HTTP or TLS dependency appears.

## Requirements

- macOS 13 Ventura or later, tested through macOS 26
- APFS (HFS+ volumes are detected and skipped)
- Apple Silicon primary; x86_64 best-effort

## Building

```bash
cargo build --release
```

## License

MIT — see [LICENSE](LICENSE).
