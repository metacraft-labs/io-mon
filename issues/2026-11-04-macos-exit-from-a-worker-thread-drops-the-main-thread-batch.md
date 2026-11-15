# macOS: exit() from a worker thread drops the main thread's record batch

|             |                                                               |
| ----------- | ------------------------------------------------------------- |
| Status      | open — shim design change, needs a decision                   |
| Observed in | io-mon `9cd683f`                                              |
| Recorded    | 2026-11-04                                                    |
| Area        | macOS shim, process-exit flush (`macos_interpose` destructor) |

## Observed

A monitored program whose main thread buffers records and which then ends
through `exit()` called on another thread loses the main thread's whole
batch: its `mrProcessStart` and every read the main thread made. The capture
fails closed. The unmatched `read-tail-pending` marker becomes
`process killed with an un-flushed read batch (kill-before-flush)`, and the
missing process-start becomes `spawn child missing process-start`. Both are
false downgrades of a process that was fully observed and exited normally.

Measured on an arm64 Mac (macOS 26.5.1, SIP disabled; SIP plays no part in
this case) against io-mon `9cd683f`, with the shim from `just build` and
`build/bin/io-mon run`. The program reads one file on the main thread and,
in `thread` mode, calls `exit(0)` from a `pthread_create`d worker while the
main thread is in `pause()`:

```c
static void *worker(void *a) { (void)a; usleep(200000); exit(0); return NULL; }
int main(int argc, char **argv) {
  int fd = open(argv[1], O_RDONLY); char b[8];
  if (fd >= 0) { read(fd, b, 8); close(fd); }
  if (argc > 2 && !strcmp(argv[2], "thread")) {
    pthread_t t; pthread_create(&t, NULL, worker, NULL); pause();
  }
  return 0;
}
```

- `main` mode (`return 0` from `main`): `mcComplete`, with the process-start
  and the `file-read` of the input.
- `thread` mode: `mcIncomplete`. There is no process-start and no
  `file-read`. The losses are `spawn child missing process-start` and one
  `kill-before-flush` for the main thread's (pid, tid).

The same thing happens to `/usr/bin/caffeinate -t 1` when SIP is off and
the shim loads into it. `/bin/cat` under the same conditions is complete. This
is why the SIP cases of `tests/macos/test_io_mon_macos_tree_lifetime_guard.nim`
report a `kill-before-flush` loss on hosts with SIP off (GitHub's hosted macOS
runners, CI run `41833671394`). That `caffeinate` exits from a dispatch
worker thread is an inference from this result. It was not traced.

## Why

The dyld `__attribute__((destructor))` flush at process exit flushes the
CALLING thread's slot only, because the batch is a threadvar (see the
"Threaded-write capture" comment in `src/io_mon/shim/macos_interpose.nim`).
The existing design covers the opposite case: worker threads flush on every
record, and the main thread keeps its batch until it flushes or exits. When
the process exits on a worker, nothing flushes the main thread's batch.

## Expected

The shim must fail closed when evidence is lost, and it does. It must also
not downgrade a process whose evidence it holds in memory at a normal
`exit()` (the hardening protocol's no-false-downgrade requirement, cited in
`2026-09-29-macos-root-evidence-test-assumes-sip-is-enabled.md`). At process
exit, the main thread's batch should be flushed whichever thread runs the
exit path. The Linux and Windows shims already run such a sweep at exit
(`flushAllRegisteredSlots` in `src/io_mon/writer.nim`); the macOS shim does
not. Two possible approaches: the exit path flushes the main thread's
slot through a pointer registered at init, under the same mute and
async-signal constraints as `repro_hook_exit`; or the main thread's
process-start and first records are flushed at init. This needs a design
decision because the main slot is not synchronized with a main thread that
may still be running.
