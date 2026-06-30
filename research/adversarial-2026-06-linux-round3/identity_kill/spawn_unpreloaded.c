#define _GNU_SOURCE
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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
  pid_t pid = 0;
  int rc = posix_spawn(&pid, argv[1], NULL, NULL, child_argv, child_env);
  if (rc != 0) {
    fprintf(stderr, "posix_spawn failed: %d\n", rc);
    return 1;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return 1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return 1;
}
