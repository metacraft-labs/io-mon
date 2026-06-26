// EVASION B: the deprecated indirect syscall(2). syscall() is itself a thin
// libsystem routine that issues SYS_syscall with the real number as its first
// arg; it does NOT call the named open/read wrappers, so the body-patch on
// `open`/`read` is bypassed and there is no import stub for interpose to rebind.
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  long fd = syscall(SYS_open, argv[1], 0 /*O_RDONLY*/, 0);
  if (fd < 0) return 1;
  char buf[256];
  long n = syscall(SYS_read, (int)fd, buf, sizeof buf);
  if (n > 0) syscall(SYS_write, 1, buf, n);
  syscall(SYS_close, (int)fd);
  return 0;
}
