// copyfile(3) with COPYFILE_ALL (data+metadata). Does it bottom out in open/read?
#include <copyfile.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  unlink(argv[2]);
  copyfile_flags_t flags = COPYFILE_ALL; // data + xattr + acl + stat
  if (copyfile(argv[1], argv[2], NULL, flags) != 0) { perror("copyfile"); return 1; }
  return 0;
}
