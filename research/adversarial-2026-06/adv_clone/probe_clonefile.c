// clonefile(2): APFS CoW clone of src -> dst. No open()/read() on src.
#include <sys/clonefile.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  unlink(argv[2]);
  if (clonefile(argv[1], argv[2], 0) != 0) { perror("clonefile"); return 1; }
  return 0;
}
