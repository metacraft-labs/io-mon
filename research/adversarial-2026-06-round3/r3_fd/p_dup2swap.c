#include <fcntl.h>
#include <unistd.h>
int main(){ char b[64];
  int fa=open("/tmp/r3_fd/marker_A.txt",O_RDONLY);   // real input
  int fb=open("/tmp/r3_fd/marker_B.txt",O_RDONLY);   // decoy
  dup2(fa,fb);            // fb now refers to A; dup2 closes old fb internally (NOT via hooked close)
  read(fb,b,sizeof b);    // reads A's content, table still says B
  close(fb); close(fa); return 0; }
