// BREAK probe: mutate an output purely via truncate(2) -- PATH based, no open, no fd.
// Shrinking truncate destroys file content (tail bytes gone); growing zero-fills.
// truncate(2) is not hooked at all.
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int c = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  const char *data = "0123456789ABCDEF0123456789ABCDEF\n"; // 33 bytes
  if (write(c, data, strlen(data)) < 0) return 2;
  close(c);
  // Mutate the output's content/identity by truncating to 8 bytes (path-based).
  if (truncate(path, 8) != 0) { perror("truncate"); return 1; }
  fprintf(stderr, "truncated %s to 8 bytes\n", path);
  return 0;
}
