#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(void){
    // 1. failed open() ENOENT (negative dep via open)
    int fd = open("absent_open.h", O_RDONLY);
    printf("open absent_open.h fd=%d\n", fd); if(fd>=0) close(fd);
    // 2. stat() ENOENT on absent file
    struct stat st; int r = stat("absent_stat.h", &st);
    printf("stat absent_stat.h r=%d\n", r);
    // 3. stat() on a DIRECTORY for its mtime (make/ninja pattern)
    int rd = stat("watchdir", &st);
    printf("stat watchdir r=%d mtime=%ld\n", rd, (long)st.st_mtime);
    // 4. output mutations: mkdir, unlink, rmdir
    mkdir("outdir", 0755);
    unlink("stale.o");
    rmdir("emptydir");
    printf("mutations done\n");
    return 0;
}
