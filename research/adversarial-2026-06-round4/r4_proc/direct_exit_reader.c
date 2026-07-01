/* r4_proc/direct_exit_reader.c — ROUND-4 V1 DETERMINISTIC integrity probe.
 *
 * The minimal trigger for the `_exit` flush gap the vfork probe (vchild.c) hits
 * only racily: a single process opens+reads a dependency, then calls `_exit(0)`
 * DIRECTLY — no `return` from main, no libc atexit handlers, no dyld destructor.
 * The shim buffers the read into its per-thread fragment batch, which is flushed
 * only on overflow / 100 ms age / the dyld process-exit destructor. `_exit`
 * bypasses the destructor and beats the 100 ms timer, so WITHOUT the V1 fix the
 * read is lost on EVERY run (0/N captured) while the merge still reports
 * mcComplete — a deterministic false-completeness (a swapped dependency would be
 * a false cache hit). vchild.c is racy because its parent returns normally and
 * the parent's destructor sometimes flushes the vfork-SHARED batch first; this
 * probe removes that confound and fails deterministically pre-fix.
 *
 * With the V1 fix (the `_exit`/`_Exit` hook flushes the batch before forwarding
 * the raw SYS_exit) the read is captured on every run.
 *
 * argv[1] = the file to read (its content is the dependency that must survive).
 */
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd >= 0) {
    char buf[256];
    (void)read(fd, buf, sizeof buf);
    close(fd);
  }
  _exit(0); /* immediate: no atexit, no destructor — the gap V1 closes */
}
