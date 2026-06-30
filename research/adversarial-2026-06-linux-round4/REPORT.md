# Linux adversarial hardening round 4

Date: 2026-06-30 through 2026-07-01
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
| 11 | Non-file determinism (`getenv`, `uname`, `sysconf`, clock, `getrandom`) | Captured by M-FW-6C for the libc-visible subset: observed-input records for env/uname/sysconf/time diagnostics plus `getrandom` non-determinism, yielding `mcIncomplete`. |

No new silent false-negative was confirmed in the newly targeted
libc-visible positioned/vector/zero-copy file-content channels. The first two
accepted fixes closed those file and path-mutation surfaces with live
regression coverage. M-FW-6C now closes the narrow libc-visible non-file
determinism subset while leaving direct raw/vDSO and broader API coverage as
capability-gated production residuals.

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

## Third fix milestone

M-FW-6C is accepted after strict review: Linux libc-visible non-file
determinism sources now use the existing observed-input/non-determinism record
model:

- `getenv` emits `mrEnvRead` with the queried variable name and does not
  downgrade by itself.
- `uname` and `sysconf` emit `mrSysctlRead` (`uname` and `sysconf:<id>`) and
  do not downgrade by themselves.
- `clock_gettime`, `gettimeofday`, and `time` emit `mrTimeRead` diagnostics
  and do not auto-downgrade, preserving the cardinal-sin guard for normal
  builds that read clocks benignly.
- Successful `getrandom` emits `mrNonDeterministic`, which the existing merge
  path maps to event-loss and `mcIncomplete`.
- Direct raw syscall and vDSO clock/time paths are not claimed by this slice.

## Follow-up candidates

- Pre-existing hardlink/inode aliases and direct raw `link*`/`rename*`
  syscall variants.
- Direct raw/vDSO and broader Linux non-file determinism APIs beyond the
  current libc-visible `getenv`/`uname`/`sysconf`/clock/time/`getrandom`
  subset.
- Direct raw zero-copy syscall classification for `sendfile`, `splice`, and
  `copy_file_range` if it can be done safely through the existing raw syscall
  event path.
