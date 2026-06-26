// EVASION F: path-fidelity bypass via the /.vol/<dev>/<inode> firmlink path.
// We resolve the file's (dev, inode) WITHOUT a hooked call — using getattrlist
// (itself unhooked) to fetch ATTR_CMN_FSID + ATTR_CMN_FILEID — then open() the
// file through its inode path /.vol/<dev>/<inode>. open() IS hooked, so a record
// is produced, BUT the recorded path is the OPAQUE inode path, never the real
// /tmp/adv_syscall/secret-volpath.txt. An incremental engine keying dependencies
// on real paths would not match this input: a path-fidelity false negative.
#include <sys/attr.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  struct attrlist al;
  memset(&al, 0, sizeof al);
  al.bitmapcount = ATTR_BIT_MAP_COUNT;
  al.commonattr = ATTR_CMN_FSID | ATTR_CMN_FILEID;
  struct {
    uint32_t len;
    fsid_t   fsid;
    uint64_t fileid;
  } __attribute__((aligned(4), packed)) ab;
  if (getattrlist(argv[1], &al, &ab, sizeof ab, 0) != 0) {
    perror("getattrlist"); return 1;
  }
  char vol[128];
  snprintf(vol, sizeof vol, "/.vol/%d/%llu", ab.fsid.val[0],
           (unsigned long long)ab.fileid);
  printf("opening via inode path: %s\n", vol);
  int fd = open(vol, O_RDONLY, 0);
  if (fd < 0) { perror("open volpath"); return 1; }
  char buf[256];
  ssize_t n = read(fd, buf, sizeof buf);
  if (n > 0) { fwrite(buf, 1, n, stdout); }
  close(fd);
  return 0;
}
