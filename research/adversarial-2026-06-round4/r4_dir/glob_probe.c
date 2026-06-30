#include <stdio.h>
#include <dirent.h>
#include <string.h>
// Simulates a build that globs *.c in srcdir and "compiles" whatever it finds.
int main(void){
    DIR *d = opendir("srcdir");
    if(!d){ printf("NO DIR\n"); return 1; }
    struct dirent *e; int count=0; char names[4096]=""; 
    while((e=readdir(d))){
        size_t n=strlen(e->d_name);
        if(n>2 && strcmp(e->d_name+n-2,".c")==0){
            strcat(names,e->d_name); strcat(names," "); count++;
        }
    }
    closedir(d);
    printf("COMPILED %d files: %s\n", count, names);
    return 0;
}
