#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

static char **env_without_ld_preload(void) {
  size_t count = 0;
  for (char **p = environ; *p; ++p) {
    if (strncmp(*p, "LD_PRELOAD=", 11) != 0) {
      count++;
    }
  }
  char **out = calloc(count + 1, sizeof(char *));
  if (!out) {
    return NULL;
  }
  size_t i = 0;
  for (char **p = environ; *p; ++p) {
    if (strncmp(*p, "LD_PRELOAD=", 11) != 0) {
      out[i++] = *p;
    }
  }
  out[i] = NULL;
  return out;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s child-reader marker\n", argv[0]);
    return 2;
  }
  char *child_argv[] = {argv[1], argv[2], NULL};
  char **child_env = env_without_ld_preload();
  if (!child_env) {
    perror("calloc");
    return 1;
  }
  long rc = syscall(SYS_execve, argv[1], child_argv, child_env);
  fprintf(stderr, "raw execve failed: rc=%ld errno=%d %s\n", rc, errno, strerror(errno));
  return 1;
}
