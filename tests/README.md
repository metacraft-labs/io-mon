# io-mon test layout

io-mon's **core is cross-platform**. The depfile model, the writer / merge /
completeness algorithm, the RMDF codec, the capabilities, and the render are
shared Nim (`src/io_mon/{writer,codec,types,render,capabilities,reader,paths}.nim`);
only the shim and hooks are per-OS (`src/io_mon/{shim,hooks,backends}/`).

The test tree mirrors that split so a regression in the shared machinery is
caught on **every** OS, while platform-specific behaviour is tested only where it
applies. The directories form the contract:

| Directory          | Runs on                                   | What belongs here |
|--------------------|-------------------------------------------|-------------------|
| `portable/`        | **every** OS                              | Pure-logic tests on shared modules. NO live shim, NO platform-specific API/import. Codec round-trip, `mergeFragments`, the completeness-downgrade algorithm on **synthetic** records, capabilities/render, the CLI build + `inspect`. |
| `posix/`           | POSIX hosts (macOS, Linux, *BSD, Solaris) | Behaviour shared across POSIX shims — e.g. the live snoop-CLI capture (DYLD on macOS / `LD_PRELOAD` on Linux) and the shim's drop-in shared-library build + exported-ABI check. |
| `macos/`           | macOS only                                | DYLD `__interpose` + `mach_vm_remap` body-patch live capture, SIP-child, XPC/Mach breakaway, content/metadata hooks, etc. |
| `linux/`           | Linux only                                | `LD_PRELOAD` shim live behaviour (placeholder for now — see `linux/README.md`). |
| `windows/`         | Windows only                              | Injected-hook live behaviour (placeholder for now — see `windows/README.md`). |
| `helpers/`         | —                                         | Shared test-only helpers (not tests). Imported via `--path:tests/helpers`. |
| `fixtures/`        | —                                         | Shared C probe sources and input fixtures. |

A test is **portable** if it only exercises shared logic (`mergeFragments`,
`readMonitorDepFile`, `encodeFrame`/`decodeFrame`, `MonitorRecord` construction,
`unmonitoredSubtreeLossCount`/`nonDeterminismObservationCount`/`depFileFromRecords`,
capabilities/render) on **synthetic** records — no `build_shim`, no
`DYLD_INSERT`/`LD_PRELOAD`, no `clang -o` probe, no `io-mon run` live capture, no
macOS-only API/import. It is **platform-specific** if it builds/injects the shim
or compiles + runs a live C probe.

## How the suite selects tests per OS

`nimble test` (see the `test` task in `io_mon.nimble`) does **directory
discovery**, not a hand-maintained list:

- it ALWAYS runs every `portable/test_*.nim`;
- it adds `posix/test_*.nim` when the host is POSIX (`when defined(posix)`);
- it adds the single native-OS dir: `macos/` (`when defined(macosx)`),
  `linux/` (`when defined(linux)`), or `windows/` (`when defined(windows)`).

The NimScript task runs on the host, so `defined(...)` reflects the host OS. Each
selected directory's `test_*.nim` files are discovered with `listFiles`, sorted
for determinism, and compiled + run with:

```
nim c -r --path:../nim-stackable-hooks/src --path:tests/helpers <file>
```

`--path:src` is supplied by the repo-root `config.nims`, and resolves correctly
no matter how deep a test file lives because the suite always runs from the repo
root. Adding a `test_*.nim` to a selected directory makes it run with **no edit
to the task**.

Convenience sub-tasks: `nimble testPortable` (only the every-OS tests) and
`nimble testPlatform` (only the host-OS platform-specific tests).

## Adding support for a new OS (e.g. FreeBSD / Solaris)

1. Create `tests/<os>/` (e.g. `tests/freebsd/`) and add a short `README.md`
   describing what live behaviour belongs there.
2. Add an arm to `selectedTestDirs()` in `io_mon.nimble`:

   ```nim
   when defined(freebsd):
     result.add "tests/freebsd"
   ```

   (POSIX OSes are already covered by the `when defined(posix)` arm, so a new
   POSIX OS automatically runs `portable/` + `posix/` even before it has its own
   directory.)
3. Put OS-specific live tests in `tests/<os>/`. Keep any pure-logic assertions in
   `portable/` so they also run everywhere else.

## Adding a test

- **Pure logic** (synthetic records, codec, merge, completeness): add it to
  `portable/`. Verify it is genuinely OS-independent with
  `nim check --os:linux --path:src --path:../nim-stackable-hooks/src <file>` —
  if it needs a macOS-only symbol it is misclassified.
- **Cross-POSIX live** behaviour: add it to `posix/` and gate any macOS-vs-Linux
  divergence with `when defined(macosx)` / `else`.
- **OS-only live** behaviour: add it to the matching per-OS dir.
