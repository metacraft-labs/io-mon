// EVASION E: getdirentries(2) directory enumeration. opendir/readdir are
// hooked, but a program can open() a directory fd and call getdirentries
// directly to read raw dirent records — no readdir wrapper is ever invoked.
// (We use the raw syscall to be sure no libsystem readdir-family wrapper runs.)
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct dirent_compat {           // matches the 64-bit getdirentries dirent
  uint64_t d_ino;
  uint64_t d_seekoff;
  uint16_t d_reclen;
  uint16_t d_namlen;
  uint8_t  d_type;
  char     d_name[1024];
};

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  int fd = open(argv[1], O_RDONLY, 0);
  if (fd < 0) { perror("open dir"); return 1; }
  char buf[16384];
  long basep = 0;
  for (;;) {
    // SYS_getdirentries64 = 344 on macOS arm64
    long n = syscall(344, fd, buf, sizeof buf, &basep);
    if (n <= 0) break;
    long off = 0;
    while (off < n) {
      struct dirent_compat *de = (struct dirent_compat *)(buf + off);
      if (de->d_reclen == 0) break;
      printf("getdirentries child: %.*s\n", (int)de->d_namlen, de->d_name);
      off += de->d_reclen;
    }
  }
  close(fd);
  return 0;
}
