#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
// fstatat against a REAL dirfd with a relative name (not AT_FDCWD).
int main(){
    int dfd=open("/tmp/r3_residual/res6/sub",O_RDONLY|O_DIRECTORY);
    if(dfd<0){perror("opendir");return 1;}
    struct stat st;
    if(fstatat(dfd,"target.txt",&st,0)<0){perror("fstatat");return 1;}
    printf("fstatat ino=%llu size=%lld\n",(unsigned long long)st.st_ino,(long long)st.st_size);
    close(dfd);
    return 0;
}
