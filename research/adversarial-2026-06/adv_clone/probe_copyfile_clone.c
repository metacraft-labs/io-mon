// copyfile(3) with COPYFILE_CLONE_FORCE — force the clonefile path.
#include <copyfile.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  unlink(argv[2]);
  if (copyfile(argv[1], argv[2], NULL, COPYFILE_CLONE_FORCE) != 0) { perror("copyfile-clone"); return 1; }
  return 0;
}
