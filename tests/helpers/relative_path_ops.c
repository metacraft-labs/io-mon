/* Relative-path operation driver for the relative-path anchoring test
 * (tests/macos/test_io_mon_macos_relative_path_anchor.nim).
 *
 * Each argument is "op:path" and is executed in order, so a test can chdir()
 * between operations and then name files by a path RELATIVE to the new cwd,
 * the way `git -C <dir>` does. Every operation's outcome is printed to stderr;
 * a failing call is part of the experiment (a negative-existence probe), so
 * only a malformed argument or an unusable dirfd makes the driver fail.
 *
 *   chdir:D       chdir(D)
 *   dirfd:D       open D as the directory fd used by the *at "d" ops below
 *   open:P        open(P, O_RDONLY)
 *   create:P      open(P, O_WRONLY|O_CREAT|O_TRUNC) and write one byte
 *   stat:P        stat(P)
 *   lstat:P       lstat(P)
 *   access:P      access(P, F_OK)
 *   openat:P      openat(AT_FDCWD, P, O_RDONLY)
 *   fstatat:P     fstatat(AT_FDCWD, P, 0)
 *   openatd:P     openat(dirfd, P, O_RDONLY)
 *   fstatatd:P    fstatat(dirfd, P, 0)
 *   opendir:P     opendir(P) + readdir until the end + closedir
 *   mkdir:P       mkdir(P, 0755)
 *   unlink:P      unlink(P)
 *   rename:A>B    rename(A, B)
 *   spawn:P       posix_spawn(P) (no PATH search) and wait for it
 *   spawnp:P      posix_spawnp(P) (PATH search for a slash-less P) and wait
 *   exec:P        fork, execve(P) in the child (no PATH search), and wait
 *   listen:P      bind + listen an AF_UNIX socket at P (kept open)
 *   connect:P     connect an AF_UNIX socket to P
 *
 * The spawned / exec'd program is run with no arguments; a copy of this
 * driver does nothing and exits 0. A failed child counts as a failed op.
 */
#include <dirent.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

/* Wait for `pid`; 0 when it exited 0, -1 otherwise. */
static long wait_ok(pid_t pid) {
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return -1;
  return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* An AF_UNIX address for `p`; -1 when it does not fit sun_path. */
static int unix_addr(const char *p, struct sockaddr_un *un) {
  memset(un, 0, sizeof *un);
  un->sun_family = AF_UNIX;
  if (strlen(p) >= sizeof un->sun_path) return -1;
  strcpy(un->sun_path, p);
  return 0;
}

int main(int argc, char **argv) {
  int dfd = -1;
  for (int i = 1; i < argc; i++) {
    char *sep = strchr(argv[i], ':');
    if (!sep) {
      fprintf(stderr, "malformed op %s\n", argv[i]);
      return 64;
    }
    *sep = '\0';
    const char *op = argv[i];
    char *p = sep + 1;
    struct stat st;
    long r = -1;
    if (!strcmp(op, "chdir")) {
      r = chdir(p);
    } else if (!strcmp(op, "dirfd")) {
      dfd = open(p, O_RDONLY | O_DIRECTORY);
      if (dfd < 0) {
        fprintf(stderr, "cannot open dirfd %s\n", p);
        return 65;
      }
      r = dfd;
    } else if (!strcmp(op, "open") || !strcmp(op, "openat") ||
        !strcmp(op, "openatd")) {
      int fd;
      if (!strcmp(op, "open"))
        fd = open(p, O_RDONLY);
      else if (!strcmp(op, "openat"))
        fd = openat(AT_FDCWD, p, O_RDONLY);
      else
        fd = openat(dfd, p, O_RDONLY);
      r = fd;
      if (fd >= 0) close(fd);
    } else if (!strcmp(op, "create")) {
      int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      r = fd;
      if (fd >= 0) {
        if (write(fd, "x", 1) != 1) r = -2;
        close(fd);
      }
    } else if (!strcmp(op, "stat")) {
      r = stat(p, &st);
    } else if (!strcmp(op, "lstat")) {
      r = lstat(p, &st);
    } else if (!strcmp(op, "access")) {
      r = access(p, F_OK);
    } else if (!strcmp(op, "fstatat")) {
      r = fstatat(AT_FDCWD, p, &st, 0);
    } else if (!strcmp(op, "fstatatd")) {
      r = fstatat(dfd, p, &st, 0);
    } else if (!strcmp(op, "opendir")) {
      DIR *d = opendir(p);
      if (d) {
        r = 0;
        while (readdir(d) != NULL) r++;
        closedir(d);
      }
    } else if (!strcmp(op, "mkdir")) {
      r = mkdir(p, 0755);
    } else if (!strcmp(op, "unlink")) {
      r = unlink(p);
    } else if (!strcmp(op, "rename")) {
      char *to = strchr(p, '>');
      if (!to) {
        fprintf(stderr, "malformed rename %s\n", p);
        return 64;
      }
      *to++ = '\0';
      r = rename(p, to);
    } else if (!strcmp(op, "spawn") || !strcmp(op, "spawnp")) {
      char *child_argv[] = {p, NULL};
      pid_t pid = 0;
      int rc;
      if (!strcmp(op, "spawn"))
        rc = posix_spawn(&pid, p, NULL, NULL, child_argv, environ);
      else
        rc = posix_spawnp(&pid, p, NULL, NULL, child_argv, environ);
      r = rc == 0 ? wait_ok(pid) : -1;
    } else if (!strcmp(op, "exec")) {
      pid_t pid = fork();
      if (pid == 0) {
        char *child_argv[] = {p, NULL};
        execve(p, child_argv, environ);
        _exit(127);
      }
      r = pid > 0 ? wait_ok(pid) : -1;
    } else if (!strcmp(op, "listen") || !strcmp(op, "connect")) {
      struct sockaddr_un un;
      int s = socket(AF_UNIX, SOCK_STREAM, 0);
      if (s < 0 || unix_addr(p, &un) != 0) {
        r = -1;
      } else if (!strcmp(op, "listen")) {
        unlink(p);
        int bound = bind(s, (struct sockaddr *)&un, sizeof un) == 0;
        r = (bound && listen(s, 4) == 0) ? 0 : -1;
        /* Keep the listener open so a later connect finds it. */
      } else {
        r = connect(s, (struct sockaddr *)&un, sizeof un);
        close(s);
      }
    } else {
      fprintf(stderr, "unknown op %s\n", op);
      return 64;
    }
    fprintf(stderr, "%s(%s)=%ld\n", op, p, r);
  }
  if (dfd >= 0) close(dfd);
  return 0;
}
