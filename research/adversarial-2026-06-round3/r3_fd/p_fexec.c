#include <fcntl.h>
#include <unistd.h>
extern char **environ;
int main(){
  int fd=open("/tmp/r3_fd/tgt",O_RDONLY); if(fd<0)return 1;
  char *argv[]={"tgt",0};
  fexecve(fd,argv,environ);
  return 99; // only if fexecve fails
}
