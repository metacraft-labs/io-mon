/* Same logical path: stat while ABSENT, then create+read. One process, one depfile.
 * Shows io-mon's own canonical form differ between the absent probe and the read. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(int argc,char**argv){
  const char*p=argv[1];
  struct stat st; int r=stat(p,&st); fprintf(stderr,"pre-stat(%s)=%d\n",p,r);
  int fd=open(p,O_RDWR|O_CREAT,0644); write(fd,"x\n",2); lseek(fd,0,0);
  char b[8]; read(fd,b,sizeof b); close(fd);
  return 0;
}
