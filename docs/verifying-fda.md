# Verifying the Full Disk Access path

`sift`'s FDA detection rests on one assumption that no test can prove:

> macOS TCC denies `read_dir` of `~/Library/Application Support/com.apple.TCC`
> with `EACCES` when Full Disk Access is not granted.

Everything downstream of that errno is covered by `tests/fda_denied.rs`, which
reproduces the denial with a mode-000 directory. The assumption itself needs a
human with System Settings open.

## When to re-verify

- The probe path or method in `caps::probe_fda` changes.
- A materially newer macOS release.
- Anyone reports `sift doctor` saying "could not determine" rather than
  "DENIED" on a machine without FDA.

## Steps

1. **System Settings → Privacy & Security → Full Disk Access**
2. Toggle **off** whatever grants your terminal access — Terminal, iTerm, or
   your editor's integrated terminal.
3. **Quit and reopen the terminal.** TCC evaluates at process start; an already
   running shell keeps its old grant and the check will silently pass.
4. Run:
   ```
   cargo run --release --quiet -- doctor
   ```
5. **Re-enable the toggle** when you are done. Other tools in that terminal lose
   disk access until you do.

## What correct looks like

```
  full disk   DENIED — some scanners cannot run
  ...
    BLOCKED  mail-downloads        needs Full Disk Access

  1 scanner(s) blocked:

  Full Disk Access — blocks: mail-downloads
```

Only `mail-downloads` appears with default config. `snapshots`, `trash`, and
`ios-backups` also require FDA but are Destructive and off by default, and a
disabled scanner is correctly reported as disabled rather than blocked —
telling someone to grant a permission for something they turned off is noise.

To see all four, enable them first:

```toml
[general]
max_risk = "destructive"

[scanners.snapshots]
enabled = true
[scanners.trash]
enabled = true
[scanners.ios-backups]
enabled = true
```

## What a failure looks like

```
  full disk   could not determine
```

This means the probe got something other than `EACCES` — most likely `ENOENT`,
which is treated as `Unknown` rather than `Granted` deliberately (claiming
access we might not have would send scanners into hard failures instead of the
clean skips FR-27 requires).

If this happens, `caps::probe_fda` needs a different detection method, and
`tests/fda_denied.rs` is no longer testing the real thing.

## Verification log

| Date | macOS | Arch | Result |
|---|---|---|---|
| 2026-08-01 | 26.5.2 | arm64 | `DENIED`, `mail-downloads` blocked. Matches the fixture exactly. |
