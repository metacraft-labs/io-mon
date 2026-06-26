// getattrlistbulk(2): bulk directory metadata scan — bypasses readdir+stat.
#include <sys/attr.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  int dirfd = open(argv[1], O_RDONLY, 0);
  if (dirfd < 0) { perror("open dir"); return 1; }
  struct attrlist al; memset(&al, 0, sizeof al);
  al.bitmapcount = ATTR_BIT_MAP_COUNT;
  al.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_MODTIME;
  char buf[16384];
  for (;;) {
    int count = getattrlistbulk(dirfd, &al, buf, sizeof buf, FSOPT_PACK_INVAL_ATTRS);
    if (count == -1) { perror("getattrlistbulk"); close(dirfd); return 1; }
    if (count == 0) break;
    char *entry = buf;
    for (int i = 0; i < count; i++) {
      uint32_t len = *(uint32_t *)entry;
      char *field = entry + sizeof(uint32_t);
      attribute_set_t returned = *(attribute_set_t *)field;
      field += sizeof(attribute_set_t);
      if (returned.commonattr & ATTR_CMN_NAME) {
        attrreference_t *ar = (attrreference_t *)field;
        printf("entry name=%s (metadata read w/o readdir/stat)\n", field + ar->attr_dataoffset);
      }
      entry += len;
    }
  }
  close(dirfd);
  return 0;
}
