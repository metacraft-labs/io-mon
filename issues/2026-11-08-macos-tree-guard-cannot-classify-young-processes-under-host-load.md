# Under host load the macOS tree-lifetime guard grades captures incomplete because it cannot classify young processes in time

|             |                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | open — narrowed to the inherent case: an unreadable process whose creator was younger than the root and is gone, or was launchd                   |
| Recorded    | 2026-11-08                                                                                                                                        |
| Observed in | io-mon @ `3d47bb1`; macOS 26 (arm64) at a load average of 103-122                                                                                 |
| Area        | `src/io_mon/macos_tree_guard.nim` (`waitForTreeQuiescence`, `sweepOnce`), `src/io_mon/macos_tree_guard.c` (`classify`), `src/io_mon/fs_snoop.nim` |

## Observed

On a heavily loaded host (load 103-122, shared with other workloads), the
per-action captures of a consumer's loopback integration test were graded
`mcIncomplete` with

```
macos tree-lifetime guard could not classify young processes after root exit unresolved=2 … images=coreutils,bash
```

so the consumer could not trust the capture. The re-run at load 84-105 was
complete: 1 incomplete capture in 2 runs.

An `unresolved` census hit is a same-user process younger than the root
whose arguments and environment the sweep could not yet read (a process
still between `fork` and `exec`, or not yet scheduled). The guard kept
sweeping until the grace window (`IO_MON_MACOS_DESCENDANT_GRACE_MS`) ended,
and then reported whatever was still unresolved. The window was a fixed
number of milliseconds, so on a starved host processes that have nothing to
do with the monitored tree stayed unresolved past it.

## What changed

Measured against io-mon `c8bc874` plus the change that updated this file.

- **The window stretches.** When the only thing keeping a round
  inconclusive is unclassified young processes, and that set is still
  changing, the window is extended up to
  `IO_MON_MACOS_DESCENDANT_GRACE_CEILING_MS` (default 5000). It stops once
  the set has stayed the same for a whole grace window, or at the ceiling
  (the loss then says `ceiling-reached`). A live member, a live ledger
  process, a growing ledger or an overflowing census still ends the window
  at the plain grace, and completion still needs a conclusive, empty round.
- **An exiting parent is classified through its own parent.**
- **An unreadable orphan is classified by its creator's unique id.** The
  kernel keeps the unique id of each process's parent as of its last fork or
  exec (`p_puniqueid`), which is not rewritten when the orphan is handed to
  launchd; it is read with `proc_pidinfo` flavor 17
  (`PROC_PIDUNIQIDENTIFIERINFO`, declared only in xnu's private header). A
  recorded parent whose id is below the root's, other than launchd and the
  monitoring process, predates the root, so the process is a non-member.
- **Every guard loss after the window names**
  `grace-ms=<n> ceiling-ms=<c> [ceiling-reached] load1=<l>`.
- Pinned deterministically by the `slow`, `exiting` and `nocreator` seams of
  `tests/macos/test_io_mon_macos_tree_lifetime_guard_faults.nim` (suite "a
  starved host"), including an orphan of an older creator (classified), an
  orphan of a younger, gone creator before and after it re-execs and a real
  launchd job (both still unclassified), a churn that completes once it
  stops, a churn that never stops (ends at the ceiling), and a surviving
  descendant that is still caught.

## What is still open

An unreadable process whose recorded creator is younger than the root and
gone, or is launchd, and which stays unreadable at every sweep until the
window ends, still grades the capture incomplete. That is fail-closed, not a
false complete, and the loss names the time spent and the load.

Launchd's id does not clear a process, although a launchd job reads it:
measured on macOS 26, an exec rewrites `p_puniqueid` to the CURRENT parent,
so an orphan of the tree that execs after launchd adopted it reads launchd's
id, 1, exactly like a job launchd started (the case "an orphan whose creator
is older … " exercises both). Nothing exported tells the two apart.

The younger-creator case is inherent without an out-of-process observer: the
creator is gone, so nothing says whether it was in the tree. Its unique id is above the root's,
like every descendant's; the tree ledger proves membership, not its absence
(a `posix_spawn` child whose creator was killed between the kernel's return
and the hook's ledger write, caught before its own shim init writes its entry,
is a real descendant missing from the ledger); and its strings are what the
census is waiting for. EndpointSecurity's fork and exec events would record
the creator's membership as it happened.

## Impact

A consumer that requires complete captures on a heavily loaded macOS machine
can still get an incomplete capture of a quiesced tree when another
workload's short-lived processes orphan unreadable children, now only after
the stretched window and with the reason and load named in the loss.
