/* Generic marker reader: opens argv[1], reads a byte, exits.
 * Compiled locally so the shim can inject (not SIP-protected). */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv){
    if(argc<2){fprintf(stderr,"usage: %s path\n",argv[0]);return 2;}
    int fd=open(argv[1],O_RDONLY);
    if(fd<0){perror("open");return 1;}
    char b[64]; ssize_t n=read(fd,b,sizeof b);
    if(n>0){ (void)write(1,b,n); }
    close(fd);
    return 0;
}
