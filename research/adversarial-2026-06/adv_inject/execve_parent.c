#include <unistd.h>
#include <stdio.h>
extern char**environ;
int main(int argc,char**argv){
  char*child[]={argv[1],argv[2],NULL};
  printf("[execve_parent] pid=%d execve %s\n",(int)getpid(),argv[1]); fflush(stdout);
  execve(argv[1],child,environ);
  perror("execve"); return 1;
}
