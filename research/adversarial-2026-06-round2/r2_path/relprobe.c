#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
int main(int argc,char**argv){
  // argv[1]=dir to chdir, argv[2]=relative path
  if(chdir(argv[1])!=0){perror("chdir");return 1;}
  struct stat st; int sr=stat(argv[2],&st);
  fprintf(stderr,"STAT rel='%s' ret=%d\n",argv[2],sr);
  int fd=open(argv[2],O_RDONLY);
  char real[1024]; real[0]=0; if(fd>=0) fcntl(fd,F_GETPATH,real);
  fprintf(stderr,"OPEN rel='%s' fd=%d F_GETPATH='%s'\n",argv[2],fd,real);
  if(fd>=0) close(fd);
  return 0;
}
