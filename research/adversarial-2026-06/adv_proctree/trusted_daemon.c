// Cooperating ("trusted") variant of daemon.c for the T3a breakaway-compensation
// proof (BuildXL "Trusted Tools / Shared Compilation" prior art). Like daemon.c
// it is started OUTSIDE the monitored invocation and reads files on a client's
// behalf — BUT it ALSO reports each read back into the client's invocation via a
// breakaway report file. For every served connection it:
//   1. obtains the CLIENT pid via getsockopt(SOL_LOCAL, LOCAL_PEERPID) — the
//      mirror of what the shim's connect hook does on the client side;
//   2. serves the requested file (the read happens here, out of tree);
//   3. writes a report into $IO_MON_BREAKAWAY_REPORT_DIR naming the client pid,
//      its own (daemon) pid, and the file it read.
// io-mon's merge folds reports whose client pid is one of the monitored
// processes: it adds the read as a real dependency AND trusts the daemon pid, so
// the build stays mcComplete BECAUSE the daemon accounted for its reads.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: trusted_daemon <sockpath> <readyfile>\n"); return 2; }
  const char *sock = argv[1];
  const char *ready = argv[2];
  const char *reportdir = getenv("IO_MON_BREAKAWAY_REPORT_DIR");

  unlink(sock);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) { perror("socket"); return 1; }
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, sock, sizeof(a.sun_path) - 1);
  if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
  if (listen(s, 16) < 0) { perror("listen"); return 1; }
  FILE *rf = fopen(ready, "w");
  if (rf) { fprintf(rf, "%d\n", getpid()); fclose(rf); }

  int seq = 0;
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0) continue;
    char path[4096];
    int pl = 0;
    char ch;
    while (pl < (int)sizeof(path) - 1 && read(c, &ch, 1) == 1) {
      if (ch == '\n') break;
      path[pl++] = ch;
    }
    path[pl] = 0;
    if (strcmp(path, "__QUIT__") == 0) { close(c); break; }

    pid_t client = 0;
    socklen_t plen = sizeof(client);
    getsockopt(c, SOL_LOCAL, LOCAL_PEERPID, &client, &plen);

    FILE *f = fopen(path, "rb");
    if (!f) { const char *e = "ERR\n"; (void)write(c, e, 4); close(c); continue; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) { if (write(c, buf, n) < 0) break; }
    fclose(f);
    close(c);

    if (reportdir && reportdir[0] && client > 0) {
      char rp[8192];
      snprintf(rp, sizeof rp, "%s/report-%d-%d-%d.io-mon-report",
               reportdir, (int)client, (int)getpid(), seq++);
      FILE *r = fopen(rp, "w");
      if (r) {
        fprintf(r, "io-mon-breakaway-report v1\nclient %d\ndaemon %d\nread %s\n",
                (int)client, (int)getpid(), path);
        fclose(r);
      }
    }
  }
  close(s);
  unlink(sock);
  return 0;
}
