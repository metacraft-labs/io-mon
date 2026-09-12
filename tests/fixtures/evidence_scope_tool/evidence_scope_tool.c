/* evidence_scope_tool — a monitored program with a KNOWN mix of lookups.
 *
 * DA-1i's `--evidence=reads-only` is a predicate on the RESULT of a lookup, so
 * grading it needs a command whose lookups have known results in both
 * directions and in numbers large enough that the difference cannot be noise
 * from the dynamic loader. This fixture performs, in order:
 *
 *   * `EVIDENCE_SCOPE_MISSES` FAILED opens   (open(2) on paths that do not exist)
 *   * `EVIDENCE_SCOPE_MISSES` FAILED probes  (stat(2) on the same paths)
 *   * one SUCCESSFUL probe and one SUCCESSFUL open+read of the input path
 *   * one write of the output path, so the harness can tell the program ran
 *
 * The absent paths are checked to BE absent: if one exists the program fails
 * loudly rather than quietly turning a failed lookup into a successful one and
 * making the record-count comparison mean something else.
 *
 * usage: evidence-scope-tool <input> <output> <missing-dir>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVIDENCE_SCOPE_MISSES 200

int main(int argc, char **argv) {
  char path[4096];
  char buffer[256];
  struct stat st;
  int i;
  int fd;
  ssize_t n;
  FILE *out;

  if (argc != 4) {
    fputs("usage: evidence-scope-tool <input> <output> <missing-dir>\n", stderr);
    return 2;
  }

  /* FAILED opens. Each is one mrFileOpen with result -1. */
  for (i = 0; i < EVIDENCE_SCOPE_MISSES; i++) {
    snprintf(path, sizeof(path), "%s/absent-open-%04d.h", argv[3], i);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
      fprintf(stderr, "fixture: %s unexpectedly exists\n", path);
      close(fd);
      return 3;
    }
  }

  /* FAILED probes. Each is one mrPathProbe with probeResult prAbsent. */
  for (i = 0; i < EVIDENCE_SCOPE_MISSES; i++) {
    snprintf(path, sizeof(path), "%s/absent-stat-%04d.h", argv[3], i);
    if (stat(path, &st) == 0) {
      fprintf(stderr, "fixture: %s unexpectedly exists\n", path);
      return 4;
    }
  }

  /* A SUCCESSFUL probe of the input — the record `reads-only` must KEEP, and
   * the one a probes-CATEGORY gate would wrongly discard. */
  if (stat(argv[1], &st) != 0) {
    perror("stat input");
    return 5;
  }

  /* A SUCCESSFUL open + read of the input. */
  fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("open input");
    return 6;
  }
  n = read(fd, buffer, sizeof(buffer));
  if (n < 0) {
    perror("read input");
    close(fd);
    return 7;
  }
  close(fd);

  out = fopen(argv[2], "w");
  if (out == NULL) {
    perror("open output");
    return 8;
  }
  fwrite(buffer, 1, (size_t)n, out);
  fclose(out);
  return 0;
}
