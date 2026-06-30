#include <stdio.h>
#include <sys/stat.h>
#include <stdio.h>
int main(void){ struct stat st;
    stat("data.txt", &st);   // regular file, stat-only (no read)
    printf("data.txt mtime=%ld size=%lld\n",(long)st.st_mtime,(long long)st.st_size);
    rename("old.o","new.o");  // rename output
    return 0; }
