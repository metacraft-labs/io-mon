#include <stdio.h>
#include <sys/stat.h>
int main(void){ struct stat st; stat("watchdir", &st);
    printf("watchdir mtime=%ld\n",(long)st.st_mtime); return 0; }
