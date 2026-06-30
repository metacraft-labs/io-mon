# Linux adversarial hardening round 4

Date: 2026-06-30
Base: io-mon `dev` after M-FW-5.
Harness: `run_round4.sh`; latest observed summary is preserved in `summary.tsv`.
Scratch artifacts: `/tmp/io_mon_linux_round4`.

## Probes run

| # | Probe | Outcome |
|---|-------|---------|
| 1 | Baseline `open`/`read`/`write` | Captured: source `mrFileRead`, output `mrFileWrite`, `mcComplete`. |
| 2 | `pread` positioned file read | Captured by the new Linux preload wrapper. |
| 3 | `readv` vector file read | Captured by the new Linux preload wrapper. |
| 4 | `preadv` positioned vector file read | Captured by the new Linux preload wrapper. |
| 5 | `sendfile` libc zero-copy file copy | Captured: source read plus destination write. |
| 6 | `copy_file_range` libc zero-copy file copy | Captured: source read plus destination write. |
| 7 | `splice` libc file-to-pipe-to-file copy | Captured: source read plus destination write. |
| 8 | Direct raw `syscall(SYS_sendfile)` | Fail-closed: unsupported raw syscall event loss, `mcIncomplete`. |
| 9 | Hardlink alias read | Residual: alias path is captured, but source identity is not connected; covered by `path-identity` gap. |
| 10 | Rename staging write | Residual: temp write is captured, final rename destination is not normalized; covered by mutation/path gaps. |
| 11 | Non-file determinism (`getenv`, `uname`, `sysconf`, clock, `getrandom`) | Residual: no records emitted by default; covered by `observed-env` and `non-determinism` gaps. |

No new silent false-negative was confirmed in the newly targeted
libc-visible positioned/vector/zero-copy file-content channels. The first fix
implemented in this round closes that narrow surface with live regression
coverage. The remaining residuals are existing capability-gated production
limits rather than newly accepted completeness claims.

## First fix milestone

M-FW-6A is ready for review: Linux libc-visible positioned/vector and
zero-copy file-content movers now record byte-moving dependencies:

- `pread`, `readv`, and `preadv` emit `mrFileRead` for the source fd.
- `sendfile`, `copy_file_range`, and `splice` emit `mrFileRead` for the
  source fd and `mrFileWrite` for the destination fd when bytes move.
- Direct raw syscall variants remain fail-closed or capability-gated; this
  pass does not claim native/backend-complete coverage.

## Follow-up candidates

- Linux rename/link/linkat/renameat/renameat2 hooks for path mutation and
  hardlink identity.
- Linux observed-env and non-determinism hooks for `getenv`, `uname`,
  `sysconf`, wall clock, and entropy.
- Direct raw zero-copy syscall classification for `sendfile`, `splice`, and
  `copy_file_range` if it can be done safely through the existing raw syscall
  event path.
