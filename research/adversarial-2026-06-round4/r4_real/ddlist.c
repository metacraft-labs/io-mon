#include <dirent.h>
#include <stdio.h>
int main(int argc, char**argv){
  DIR*d=opendir(argv[1]); if(!d)return 2;
  struct dirent*e; while((e=readdir(d))) printf("%s\n", e->d_name);
  closedir(d); return 0;
}
