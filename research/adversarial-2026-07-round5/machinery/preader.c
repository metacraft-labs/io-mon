#include <fcntl.h>
#include <unistd.h>
int main(){char b[64];int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);int n=read(f,b,sizeof b);write(1,b,n);close(f);return 0;}
