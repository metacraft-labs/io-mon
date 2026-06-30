/* Opens a symlink path and reads it, while a helper thread flips the symlink
 * target between two real files. Tests whether the recorded canonical (F_GETPATH)
 * read dependency ever attributes to the WRONG file's content. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static char link_path[600], realA[600], realB[600];
static volatile int stop=0;

void* flipper(void* _){
  for(int i=0;!stop;i++){
    unlink(link_path);
    symlink((i&1)?realA:realB, link_path);
  }
  return NULL;
}

int main(int argc,char**argv){
  // argv[1]=dir
  snprintf(realA,sizeof realA,"%s/realA.txt",argv[1]);
  snprintf(realB,sizeof realB,"%s/realB.txt",argv[1]);
  snprintf(link_path,sizeof link_path,"%s/thelink",argv[1]);
  unlink(link_path); symlink(realA, link_path);
  pthread_t t; pthread_create(&t,NULL,flipper,NULL);
  for(int i=0;i<400;i++){
    int fd=open(link_path,O_RDONLY);
    if(fd<0) continue;
    char buf[64]; ssize_t n=read(fd,buf,sizeof buf-1);
    if(n>0){ buf[n]=0; }
    close(fd);
  }
  stop=1; pthread_join(t,NULL);
  return 0;
}
