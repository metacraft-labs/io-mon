// EVASION C: getattrlist(2) — an existence + metadata probe that is NOT on the
// hook list (only stat/lstat/fstatat/access are). A build tool that checks
// "does this header exist / what is its mtime" via getattrlist leaves NO
// recorded stat/probe, so the dependency is invisible.
#include <sys/attr.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  struct attrlist al;
  memset(&al, 0, sizeof al);
  al.bitmapcount = ATTR_BIT_MAP_COUNT;
  al.commonattr = ATTR_CMN_MODTIME | ATTR_CMN_OBJTYPE;
  struct { uint32_t len; struct timespec mtime; } __attribute__((aligned(4), packed)) buf;
  int rc = getattrlist(argv[1], &al, &buf, sizeof buf, 0);
  if (rc != 0) { perror("getattrlist"); return 1; }
  printf("getattrlist OK: existence+mtime probed for %s\n", argv[1]);
  return 0;
}
