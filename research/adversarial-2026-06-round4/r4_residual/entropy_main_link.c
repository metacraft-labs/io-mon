/* Build tool LINKED against entropy_lib; bakes the random value into output. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
unsigned draw_entropy(void);
int main(int argc,char**argv){
  unsigned r=draw_entropy();
  int fd=open(argv[1],O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(fd,"nondeterministic-output: %u\n",r); close(fd);
  return 0;
}
