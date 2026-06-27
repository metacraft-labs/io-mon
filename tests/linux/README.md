# tests/linux — Linux-only tests (placeholder)

This directory holds tests that exercise io-mon's **Linux-only** live behaviour:
the `LD_PRELOAD` interpose shim (`src/io_mon/shim/linux_preload.nim`,
`src/io_mon/hooks/linux_preload_runtime.nim`) actually injected into a recorded
process.

It is selected by the suite only `when defined(linux)` (see the `test` task in
`io_mon.nimble`). Any `test_*.nim` added here runs automatically on a Linux host.

## What belongs here (vs. elsewhere)

- **Here (`linux/`):** behaviour that is specific to the `LD_PRELOAD` mechanism
  or to Linux kernel/libc surfaces (e.g. `/proc`, `clone(2)` flags, glibc
  internal-call coverage) and has no macOS analogue.
- **`posix/`:** behaviour shared with the other POSIX shims — e.g. the live
  snoop-CLI capture, which already runs on Linux from `posix/` and asserts the
  `LD_PRELOAD` path captures a freshly-built user binary's read.
- **`portable/`:** the shared writer/merge/codec/completeness logic on synthetic
  records — those already run on Linux and must NOT be duplicated here.

No Linux-only live tests exist yet; the cross-POSIX coverage in `posix/`
exercises the Linux shim where it overlaps macOS. Add focused Linux-only cases
here as the Linux backend grows (it currently shares the POSIX capture path).
