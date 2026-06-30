#include <stdio.h>
#include <dirent.h>
#include <string.h>
int main(void){
    DIR *d = opendir("srcdir");
    if(!d){ printf("NO DIR\n"); return 1; }
    struct dirent *e;
    while((e=readdir(d))){
        printf("ENTRY name='%s' len=%zu reclen=%u\n", e->d_name, strlen(e->d_name), e->d_reclen);
    }
    closedir(d);
    return 0;
}
