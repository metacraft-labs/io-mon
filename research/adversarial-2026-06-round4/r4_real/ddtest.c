#include <dirent.h>
#include <stdio.h>
int main(int argc, char**argv){
  DIR*d=opendir(argv[1]);
  if(!d){perror("opendir");return 2;}
  int n=0; struct dirent*e; int sawinit=0;
  while((e=readdir(d))){ n++; if(!__builtin_strcmp(e->d_name,"__init__.py"))sawinit=1; }
  closedir(d);
  printf("readdir entries=%d saw__init__=%d\n", n, sawinit);
  return 0;
}
