# Linux: posix_spawn with a chdir file action reports a false loss when the child exits before the re-check

|             |                                                                         |
| ----------- | ----------------------------------------------------------------------- |
| Status      | open — design change, needs a human decision                            |
| Observed in | io-mon `b60947c` (the behaviour arrived in `6fc4ba9`, already on `dev`) |
| Recorded    | 2026-11-04                                                              |
| Area        | Linux shim, `posix_spawn` / `posix_spawnp` hooks, post-spawn re-check   |

## Observed

A `posix_spawn` whose file actions change the child's directory
(`posix_spawn_file_actions_addchdir_np` / `addfchdir_np`) is classified a
second time after the spawn succeeds, from the child itself:
`ct_linux_spawn_image_uninjectable` in
`src/io_mon/hooks/linux_preload_runtime.nim` reads `/proc/<child>/exe`, then
resolves the name in `/proc/<child>/cwd`. When neither can be read and the
name depends on the directory, the entry is reported as an event-loss
(`spawned image unverifiable: the child exited before the directory its file
actions chose could be read image=<name>`, or the unnamed frame when the
thread cannot record), and the capture is `mcIncomplete`.

glibc's `posix_spawn` returns once the child has exec'd, and the re-check runs
right after that, inside the hook. A child that is an ordinary dynamic image
the shim enters, but that exits quickly, is often already a zombie by then: a
zombie's `exe` and `cwd` links cannot be read, so the re-check fails closed
and grades a fully observed child as a loss.

Measured on nixos-ci-bare-002 (x86_64-linux, load average 140–160) against
io-mon `b60947c`, with the shim from `just build`. The program spawned
`./t` (`int main(void){return 0;}`, an ordinary dynamic executable) 300
times with an `addchdir_np` file action into its directory, waiting for each
child, under `io-mon run`:

```c
for (int i = 0; i < n; i++) {
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addchdir_np(&fa, dir);
  pid_t pid; char *argv[] = {"./t", 0};
  posix_spawn(&pid, "./t", &fa, 0, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  int st; waitpid(pid, &st, 0);
}
```

Two runs gave **58 and 72 false losses per 300 spawns**, every one
`uninjectable image: posix_spawn: spawned image unverifiable: the child exited
before the directory its file actions chose could be read image=./t`.

The same race made the control "a chdir file action before an ordinary 64-bit
image" in `tests/linux/test_io_mon_uninjectable_image_entry.nim` fail in 2 of
2 full runs on that host (`just test` and the reprobuild-env `repro test`),
both times in the arm whose thread cannot record. A review re-run of that test
binary alone, built from a clean checkout of `b60947c` on the same host (load
average 280–420), failed in 5 of 10 runs: the recording arm failed in all 5 and
the arm that cannot record in 2 of them, every loss naming
`spawned image unverifiable … image=./helper64-chdir`. That control now holds its
child alive across the re-check, so it grades the re-check of a live child;
the gap itself is this issue.

## Expected

The correctness contract (`docs/contributors/architecture.md` §2) makes a
false _complete_ the cardinal sin and downgrades every uncertainty to
`mcIncomplete`. Failing closed on a child the shim genuinely cannot verify is
therefore correct, and must stay. What the contract does not say is whether
the shim may leave an ordinary, injectable child unverifiable merely because
it exited quickly.

Not specified. Proposed: a spawned child that the shim entered (an ordinary
dynamic image of the right class) must not be graded as a loss only because
it exited before the parent's re-check. A false loss is not unsound, but it
makes the action uncacheable and, at the measured rate, any step that spawns
short-lived children with a chdir file action will almost never be cached.

## Fix options (each a design change)

1. **Record the directories at the file-action call.** Hook
   `posix_spawn_file_actions_addchdir_np` and `addfchdir_np`, remember the
   directory (or a duplicated descriptor) per `posix_spawn_file_actions_t`,
   and classify the name in that directory **before** the spawn, as the
   no-file-action path already does. The post-spawn `/proc` read then becomes
   unnecessary. Costs: two new hooks, lifetime tracking until
   `posix_spawn_file_actions_destroy`, and the actions object remains opaque
   for any other action that changes resolution.
2. **Settle it from the child's own process-start record.** The shim in a
   child it enters emits `mrProcessStart` for that pid. When the parent's
   re-check finds the child unreadable, emit a provisional marker instead of
   the loss, and let the host-side merge discharge it if the child's
   `process-start` (with the expected image) is present, and keep the loss
   otherwise. Costs: a new record shape or detail, and merge logic that must
   never discharge a marker for a child that ran an uninjectable image first
   (the case this re-check exists for: an uninjectable image that exec'd on
   into a monitored one in the same pid). Since every process-start now
   carries the image its process runs (`/proc/self/exe`, read at shim init;
   docs/usage.md, "The process-start image"), the merge has the "expected
   image" to compare against without any new child-side record; the marker
   and the merge rule remain.

Neither is a local fix; both change the shim/host contract and need a human
decision before implementation.

## Related

- The detail text says "the child exited", but the same arm is reached by a
  live child whose `/proc` links are unreadable (a non-dumpable child, for
  example after exec of an image the caller may not read). The new test "a
  chdir file action before a child whose /proc entries are unreadable" uses
  that to grade the fail-closed arm deterministically.
