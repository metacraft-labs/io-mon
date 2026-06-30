#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>
int main(int argc, char** argv){
    char names[1024]; ssize_t ln = listxattr(argv[1], names, sizeof(names), 0);
    if(ln<0){perror("listxattr");return 2;}
    /* output branches on whether a marker attr is present */
    int found=0; for(char*p=names; p<names+ln; p+=strlen(p)+1) if(!strcmp(p,"com.example.gate")) found=1;
    int fd=open(argv[1],O_RDONLY); char buf[256];
    ssize_t fn=fgetxattr(fd,"com.example.gate",buf,sizeof(buf)-1,0,0); close(fd);
    if(fn<0){perror("fgetxattr");return 3;} buf[fn]=0;
    printf("LIST_FOUND=%d FGET=[%s]\n",found,buf);
    return 0;
}
