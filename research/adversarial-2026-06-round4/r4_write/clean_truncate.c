// CLEAN BREAK: pre-existing file, mutate via path-based truncate(2) ONLY -- no open
// at all. truncate(2) is not hooked => zero records reference the mutated output.
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  if (truncate(path, 4) != 0) { perror("truncate"); return 1; } // NOT hooked
  fprintf(stderr, "truncate mutated %s to 4 bytes\n", path);
  return 0;
}
