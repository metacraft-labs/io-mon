// exchangedata(2): atomic swap of two files' content/inodes. No open/read.
#include <unistd.h>
#include <stdio.h>
int exchangedata(const char *, const char *, unsigned int);
int main(int argc, char **argv) {
  if (exchangedata(argv[1], argv[2], 0) != 0) { perror("exchangedata"); return 1; }
  return 0;
}
