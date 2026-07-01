#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
int main(int argc,char**argv){
  int dirfd=open(argv[1],O_RDONLY|O_DIRECTORY,0);
  if(dirfd<0){perror("open");return 1;}
  DIR*d=fdopendir(dirfd);
  if(!d){perror("fdopendir");return 2;}
  struct dirent*e; int found=0;
  while((e=readdir(d))){ if(argc>2&&strcmp(e->d_name,argv[2])==0){found=1;printf("FOUND:%s\n",e->d_name);} }
  closedir(d);
  return found?0:9;
}
