#define _GNU_SOURCE
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: ldso_direct_exec <ld-linux> <reader> <marker>\n");
    return 2;
  }
  char *child_argv[] = {argv[1], argv[2], argv[3], NULL};
  char *child_env[] = {"PATH=/usr/bin:/bin", NULL};
  long rc = syscall(SYS_execve, argv[1], child_argv, child_env);
  perror("syscall execve ld-linux");
  return (int)rc;
}
