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
| 9 | Hardlink alias read | Captured by M-FW-6B for libc-visible `link`/`linkat`: source identity is recorded as a file read and the alias as a write. |
| 10 | Rename staging write | Captured by M-FW-6B for libc-visible `rename`/`renameat`/`renameat2`: final destination path is recorded as a write. |
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

## Second fix milestone

M-FW-6B is ready for review: Linux libc-visible path mutation and identity
helpers now record successful path moves and hardlink creation:

- `link` and `linkat` emit `mrFileRead` for the source path and `mrFileWrite`
  for the alias path, so an alias read is no longer disconnected from the
  source identity created in the monitored process.
- `rename`, `renameat`, and the best-effort exported `renameat2` wrapper emit
  `mrFileWrite` for the final destination path, so temp-file staging does not
  leave evidence only on the temporary path.
- Failed mutation syscalls do not emit successful read/write evidence.
- Dirfd-relative `linkat`/`renameat` paths are resolved through the monitored
  fd table before recording.

## Follow-up candidates

- Pre-existing hardlink/inode aliases and direct raw `link*`/`rename*`
  syscall variants.
- Linux observed-env and non-determinism hooks for `getenv`, `uname`,
  `sysconf`, wall clock, and entropy.
- Direct raw zero-copy syscall classification for `sendfile`, `splice`, and
  `copy_file_range` if it can be done safely through the existing raw syscall
  event path.
