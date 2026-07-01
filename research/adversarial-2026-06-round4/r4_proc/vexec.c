/* r4_proc/vexec.c — ROUND-4 V1 cardinal-sin / no-regression probe.
 *
 * The REALISTIC vfork pattern: vfork() + immediately execve() in the child (the
 * canonical "fast spawn" libc/shell idiom). The exec hook flushes the child's
 * batch synchronously and re-loads the shim into the new image (which emits its own
 * process-start), so the child is fully captured. The V1 fix must NOT regress this.
 *
 * argv[1] = a program to exec; argv[2..] = its arguments.
 */
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  pid_t pid = vfork();
  if (pid == 0) {
    /* vfork CHILD: exec immediately (the held, realistic pattern). */
    execv(argv[1], &argv[1]);
    _exit(127); /* exec failed */
  }
  if (pid < 0) return 3;
  int st;
  while (waitpid(pid, &st, 0) < 0) { /* retry on EINTR */ }
  return 0;
}
