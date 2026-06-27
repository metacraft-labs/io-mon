#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char**argv){
  if(argc<2){fprintf(stderr,"usage: probe <path>...\n");return 2;}
  for(int i=1;i<argc;i++){
    int fd=open(argv[i],O_RDONLY);
    if(fd<0){perror(argv[i]);continue;}
    char b[64]; ssize_t n=read(fd,b,sizeof b);
    char real[1024]; real[0]=0;
    fcntl(fd,F_GETPATH,real);
    fprintf(stderr,"OPENED arg='%s' F_GETPATH='%s' read=%zd\n",argv[i],real,n);
    close(fd);
  }
  return 0;
}
