/* Control fixture for the completeness-under-contention battery (D).
 * Forks N children that each read the marker file and exit cleanly. With no
 * kill this is a fully monitored tree (mcComplete). With "kill" one child is
 * SIGKILLed after it has read+published its dependency, proving io-mon stays
 * honest (LF-7: the killed leaf's read is retained; no false loss). */
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
  if (argc < 3) return 64;
  const char *marker = argv[1];
  int n = atoi(argv[2]);
  int dokill = argc > 3 && strcmp(argv[3], "kill") == 0;
  if (n < 1 || n > 64) return 65;
  pid_t pids[64];
  char buf[64];
  for (int i = 0; i < n; i++) {
    pid_t p = fork();
    if (p == 0) {
      int fd = open(marker, O_RDONLY);
      if (fd < 0) _exit(2);
      if (read(fd, buf, sizeof(buf)) < 0) _exit(3);
      close(fd);
      if (dokill && i == 0) { for (;;) pause(); } /* victim: killed after read */
      _exit(0);
    }
    pids[i] = p;
  }
  if (dokill) { usleep(60000); kill(pids[0], SIGKILL); }
  for (int i = 0; i < n; i++) { int st; waitpid(pids[i], &st, 0); }
  return 0;
}
