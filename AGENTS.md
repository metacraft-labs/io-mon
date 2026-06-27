# AGENTS.md — io-mon

Repo-specific notes only. (For the monitor's scope, the CLI/library API, and the
hardening process, see `README.md`, `docs/usage.md`, and
`reprobuild-specs/io-mon-hardening-protocol.md`.)

## Build & test

- Build the injected shim: `repro build io-mon:shim` (fallback: `scripts/build_shim.sh`).
- Build the CLI (`build/bin/io-mon`): `repro build io-mon` (fallback: `nimble buildSnoop`).
- Run the suite: `repro build io-mon:test` (fallback: `nimble test`).
  - `nimble test` auto-selects `tests/portable` + the host OS's dirs.
  - `nimble testPortable` — only the every-OS tests. `nimble testPlatform` — only
    the host's platform-specific tests.
- `nim-stackable-hooks` is resolved as a sibling checkout at
  `../nim-stackable-hooks/src` (not a nimble dep). The bare-`nim` dev path can be
  flaky with that `--path`; prefer the nimble tasks.

## Tests are organized by portability

`test_*.nim` files are auto-discovered per directory — no manual registration.

| dir | runs on | put here |
|-----|---------|----------|
| `tests/portable/` | every OS | pure-logic: codec, depfile read/write, `mergeFragments`, the completeness algorithm on **synthetic** records. NO live shim, NO platform API/import. |
| `tests/posix/` | macOS, Linux, *BSD, Solaris | behavior shared across POSIX shims |
| `tests/macos/` | macOS only | DYLD interpose + body-patch live capture |
| `tests/linux/` | Linux only | LD_PRELOAD live capture |
| `tests/windows/` | Windows only | injected-hook live capture |
| `tests/helpers/` | — | shared test helpers (not tests) |
| `tests/fixtures/` | — | C probe sources |

Rules:
- A test that builds/injects the shim or compiles+runs a live C probe is
  platform-specific (goes in `macos/`/`linux/`/etc.). Everything else — the
  shared `src/io_mon/{writer,codec,types,render,capabilities}.nim` logic — is
  **portable**; prefer `tests/portable/` so a regression is caught on every OS.
- When a feature has both shared logic and live behavior, split it: the
  synthetic-record assertions in `tests/portable/`, the live capture in the
  platform dir.
- Adding a new OS (e.g. FreeBSD): create `tests/freebsd/` and add a
  `when defined(freebsd): result.add "tests/freebsd"` line to `selectedTestDirs()`
  in `io_mon.nimble`.
- Don't weaken or skip an assertion to make a change pass.
