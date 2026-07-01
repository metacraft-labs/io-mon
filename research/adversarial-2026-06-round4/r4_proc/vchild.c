/* r4_proc/vchild.c — ROUND-4 V1 integrity probe.
 *
 * A vfork() child that does open+read+_exit (NO exec). The child shares the
 * parent's address space — including the shim's per-thread fragment batch + the
 * kill-before-flush sentinel state. The child's _exit tears the child down WITHOUT
 * running the shim destructor, then the parent exits cleanly. The buffered read can
 * be lost (~36% racy) while the merge still reports mcComplete — an integrity gap.
 *
 * POSIX-UB pattern (a vfork child may legally only call _exit/exec), low real-tool
 * likelihood, but a real lost-read + false-mcComplete must not happen.
 *
 * argv[1] = the file the vfork child reads (its content is the "lost" dependency).
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  pid_t pid = vfork();
  if (pid == 0) {
    /* vfork CHILD: open+read the dependency file, then _exit WITHOUT exec. */
    int fd = open(argv[1], O_RDONLY);
    if (fd >= 0) {
      char buf[256];
      (void)read(fd, buf, sizeof buf);
      close(fd);
    }
    _exit(0);
  }
  if (pid < 0) return 3;
  int st;
  while (waitpid(pid, &st, 0) < 0) { /* retry on EINTR */ }
  return 0;
}
