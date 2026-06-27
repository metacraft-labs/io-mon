#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// usage: sprobe <op> <path>   op in {stat,lstat,access}
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage: sprobe <stat|lstat|access> <path>\n");return 2;}
  struct stat st;
  int r=-1;
  if(!strcmp(argv[1],"stat")) r=stat(argv[2],&st);
  else if(!strcmp(argv[1],"lstat")) r=lstat(argv[2],&st);
  else if(!strcmp(argv[1],"access")) r=access(argv[2],R_OK);
  fprintf(stderr,"OP=%s arg='%s' ret=%d\n",argv[1],argv[2],r);
  return 0;
}
