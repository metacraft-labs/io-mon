# Linux: the descendant guard misses a descendant that overwrote its environment

|             |                                                                  |
| ----------- | ---------------------------------------------------------------- |
| Status      | open (not reproduced on Linux yet; the macOS form is reproduced) |
| Observed in | io-mon `6fccd92` plus the uncommitted macOS tree-lifetime guard  |
| Recorded    | 2026-10-30                                                       |
| Area        | Linux §4.1 scan (`fs_snoop.liveInjectedDescendants`), Linux shim |

## Observed (macOS), expected to hold on Linux

The macOS tree-lifetime guard's census read each process's live
argument/environment area (`KERN_PROCARGS2`) for this run's needles
(`REPRO_MONITOR_SESSION=<runId>`, `REPRO_MONITOR_FRAGMENT_DIR=<dir>`). A
double-forked, `setsid` daemon grandchild that overwrote those strings in
place (`memset` over each `REPRO_MONITOR_*` entry of `environ`) and then
stayed alive was invisible to it, and the capture was graded `mcComplete`
while the daemon was still running. PostgreSQL 16 does the same thing on
Darwin as a side effect of setting its process title (`ps_status.c`,
`PS_USE_CLOBBER_ARGV`): it moves the environment to the heap and reuses the
whole argv+environ area.

The Linux scan reads `/proc/<pid>/environ`. That file is also a view of the
process's live memory (the `env_start..env_end` range of its stack), not a
copy taken at exec, so the same overwrite should hide the process from it.
On Linux, PostgreSQL uses `PS_USE_CLOBBER_ARGV` too.

## Repro (to run on Linux)

The macOS fixture is `tests/macos/test_io_mon_macos_tree_lifetime_guard.nim`
case 10 (`daemon ... gated 0 clobber` and `... pgtitle`). The same C fixture
builds on Linux. Run it under `runMonitored`, hold the grandchild alive past
`finishMonitor`, and expect `mcIncomplete`; with the current scan it should
come back `mcComplete`.

## What macOS did (the fix to port)

macOS now keeps a **tree ledger** (`src/io_mon/tree_ledger.nim`): one empty
file `repro-tree-<pid>-<start>.iomon-tree` in the fragment directory per
process the shim saw come into existence, written synchronously and not gated
by the event interest. The shim writes it at shim init, in the child and the
parent of a hooked `fork` / `posix_spawn` (the parent before the call
returns), and in the exec hook. After the root exits, the guard checks every
entry for liveness against the census snapshot, re-reads the ledger to make
sure no entry appeared meanwhile, and fails closed on a failed write or a
ledger without the root's entry. The soundness argument is in the header of
`src/io_mon/macos_tree_guard.nim`.

The record stream cannot replace the ledger on Linux either:
`mrProcessStart` / `mrProcessSpawn` are batched until the producer flushes
(a quiet live process never does), they are gated by `ecProcessTree`, the
Linux records carry no start time, and on Linux they travel through the
`nim-shm-gset` set, which settle would have to snapshot a second time.

Porting it needs:

- the start time in the entry name in Linux units (field 22 of
  `/proc/<pid>/stat`, USER_HZ ticks since boot, the unit `rootStartTicks`
  already uses), read in the shim for itself at init and for the child after
  `fork` / `posix_spawn` returns; that is one extra `/proc` read per process
  and per spawn;
- `liveInjectedDescendants`' loop to check the entries (state not `Z`, same
  start ticks) and to re-read the ledger, as the macOS loop does;
- a Linux `clobber` and `pgtitle` test, verified on x86_64 (the aarch64 Nix
  linux-builder fails the descendant-guard tests on the base revision too).

## Related: stale objects from `{.compile.}`

`src/io_mon/shim/linux_private_heap.c` (compiled under
`-d:ioMonGlibcPrivateHeap`) had the same stale-object hazard as
`macos_tree_guard.c`: Nim reuses a `{.compile.}` object whenever it is newer
than the source. Both now name the object after a hash of the C source. The
Linux change compiles in the default build only under that define; check it
on Linux when this issue is worked.
