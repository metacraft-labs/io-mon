#include <unistd.h>
extern char **environ;
int main(){ char *argv[]={"tgt",0}; execve("/tmp/r3_fd/tgt_link",argv,environ); return 99; }
