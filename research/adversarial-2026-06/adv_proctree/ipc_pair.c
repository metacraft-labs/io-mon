// Cardinal-sin guard probe (T3a): two MONITORED processes that legitimately talk
// over an AF_UNIX socket must NOT downgrade completeness. The parent (run under
// io-mon) creates a listening socket and posix_spawns a SECOND copy of itself in
// "child" mode; the child (re-injected via the propagated DYLD env, so it loads
// the shim and emits its own process-start) connects back and sends a byte. Both
// are inside the injected tree, so the client-side connect's peer pid (the
// parent, obtained via LOCAL_PEERPID) HAS a matching process-start ⇒ no
// downgrade. Self-spawn (rather than fork) is used so the child is a fresh exec
// that re-runs the shim constructor and flushes its fragment on a normal exit.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

extern char **environ;

static int run_child(const char *sock) {
  int c = socket(AF_UNIX, SOCK_STREAM, 0);
  if (c < 0) { perror("socket"); return 3; }
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, sock, sizeof(a.sun_path) - 1);
  if (connect(c, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 4; }
  if (write(c, "x", 1) != 1) { perror("write"); close(c); return 5; }
  close(c);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: ipc_pair <sockpath> [child]\n"); return 2; }
  const char *sock = argv[1];
  if (argc >= 3 && strcmp(argv[2], "child") == 0) {
    return run_child(sock);
  }

  unlink(sock);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) { perror("socket"); return 1; }
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, sock, sizeof(a.sun_path) - 1);
  if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
  if (listen(s, 4) < 0) { perror("listen"); return 1; }

  char *child_argv[] = { argv[0], (char *)sock, "child", NULL };
  pid_t pid = 0;
  int rc = posix_spawn(&pid, argv[0], NULL, NULL, child_argv, environ);
  if (rc != 0) { fprintf(stderr, "posix_spawn: %d\n", rc); return 1; }

  int cc = accept(s, NULL, NULL);
  if (cc >= 0) { char b; (void)read(cc, &b, 1); close(cc); }
  int st = 0;
  waitpid(pid, &st, 0);
  close(s);
  unlink(sock);
  printf("ipc_pair parent done child_status=%d\n", st);
  return 0;
}
