// EVASION D: getattrlistbulk(2) directory enumeration. The monitor hooks
// opendir/readdir/closedir, but getattrlistbulk reads an entire directory's
// entries (names + attrs) via a plain open() fd + the getattrlistbulk syscall —
// no readdir is ever called. We open the DIRECTORY (that open IS recorded as a
// dir open), but the per-entry enumeration that discovers child filenames is
// invisible: a tool that lists a dir this way to decide which inputs exist
// records no readdir/enumerate for the children it learned about.
#include <sys/attr.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  int dirfd = open(argv[1], O_RDONLY, 0);
  if (dirfd < 0) { perror("open dir"); return 1; }
  struct attrlist al;
  memset(&al, 0, sizeof al);
  al.bitmapcount = ATTR_BIT_MAP_COUNT;
  al.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
  char buf[8192];
  for (;;) {
    int count = getattrlistbulk(dirfd, &al, buf, sizeof buf, 0);
    if (count < 0) { perror("getattrlistbulk"); close(dirfd); return 1; }
    if (count == 0) break;
    char *entry = buf;
    for (int i = 0; i < count; i++) {
      uint32_t length = *(uint32_t *)entry;
      attribute_set_t returned = *(attribute_set_t *)(entry + sizeof(uint32_t));
      char *field = entry + sizeof(uint32_t) + sizeof(attribute_set_t);
      if (returned.commonattr & ATTR_CMN_NAME) {
        attrreference_t nameref = *(attrreference_t *)field;
        const char *name = field + nameref.attr_dataoffset;
        printf("enumerated child: %s\n", name);
      }
      entry += length;
    }
  }
  close(dirfd);
  return 0;
}
