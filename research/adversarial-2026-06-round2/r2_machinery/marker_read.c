#include <unistd.h>
#include <fcntl.h>
int main(int argc, char**argv){
  char buf[64];
  for(int i=1;i<argc;i++){
    int fd=open(argv[i],O_RDONLY);
    if(fd>=0){ (void)!read(fd,buf,sizeof buf); close(fd);}
  }
  return 0;
}
