// link(2): hardlink — new name for the SAME inode/content of src. No open/read.
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
  unlink(argv[2]);
  if (link(argv[1], argv[2]) != 0) { perror("link"); return 1; }
  return 0;
}
