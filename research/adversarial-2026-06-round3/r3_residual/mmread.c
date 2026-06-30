#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
// Reads a file PURELY via mmap PROT_READ on an O_RDONLY fd. Never calls read().
int main(int argc,char**argv){
    int fd=open(argv[1],O_RDONLY);
    if(fd<0){perror("open");return 1;}
    struct stat st; fstat(fd,&st);
    char*p=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(p==MAP_FAILED){perror("mmap");return 1;}
    unsigned long sum=0; for(off_t i=0;i<st.st_size;i++) sum+=(unsigned char)p[i]; // touch via memory
    munmap(p,st.st_size); close(fd);
    printf("mmap-read %ld bytes checksum=%lu\n",(long)st.st_size,sum);
    return 0;
}
