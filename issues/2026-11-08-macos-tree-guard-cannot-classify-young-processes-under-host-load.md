# Under host load the macOS tree-lifetime guard grades captures incomplete because it cannot classify young processes in time

|             |                                                                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                                                                     |
| Recorded    | 2026-11-08                                                                                                                               |
| Observed in | io-mon @ `3d47bb1`; macOS 26 (arm64) at a load average of 103-122                                                                        |
| Area        | `src/io_mon/macos_tree_guard.nim` (`waitForTreeQuiescence`, `sweepOnce`), `src/io_mon/fs_snoop.nim` (`IO_MON_MACOS_DESCENDANT_GRACE_MS`) |

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
still between `fork` and `exec`, or not yet scheduled). The guard keeps
sweeping until the grace window (`IO_MON_MACOS_DESCENDANT_GRACE_MS`) ends,
and then reports whatever is still unresolved. The window is a fixed number
of milliseconds, so on a starved host processes that have nothing to do with
the monitored tree (or a tree member that is about to exit) stay unresolved
past it.

## Expected

The guard fails closed, which is correct (a capture is complete only
when no recorded or marked descendant survives), so this is not a soundness
defect. But a capture of a quiesced tree should not depend on how busy the
host is. Options worth measuring:

- extend the window while the set of unresolved pids is still changing
  (each one a new young process), bounded by a hard ceiling;
- resolve a young process by its parent chain or by the tree ledger before
  reading its strings, so a process provably outside the tree never needs
  its strings read;
- report the grace actually spent and the host load in the loss detail, so a
  consumer can tell this case from a real surviving descendant.

## Impact

A consumer that requires complete captures on a busy macOS machine gets
them only intermittently: its integration tests fail under load although
the monitored tree quiesced.
