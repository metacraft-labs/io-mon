#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: exec_env_scrub <reader> <marker>\n");
    return 2;
  }
  char *child_argv[] = {argv[1], argv[2], NULL};
  char *child_env[] = {"PATH=/usr/bin:/bin", NULL};
  execve(argv[1], child_argv, child_env);
  perror("execve");
  return 1;
}
