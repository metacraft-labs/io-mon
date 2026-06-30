#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
// use getdirentries(2) directly
extern int getdirentries(int, char*, int, long*);
int main(int argc,char**argv){
  int fd=open(argv[1],O_RDONLY|O_DIRECTORY); if(fd<0){perror("open");return 2;}
  char buf[8192]; long base=0; int n,saw=0,cnt=0;
  while((n=getdirentries(fd,buf,sizeof(buf),&base))>0){
    int off=0;
    while(off<n){ struct dirent*e=(struct dirent*)(buf+off);
      if(e->d_reclen==0)break;
      cnt++; if(!__builtin_strcmp(e->d_name,"__init__.py"))saw=1;
      off+=e->d_reclen; }
  }
  close(fd); printf("getdirentries entries=%d saw__init__=%d\n",cnt,saw); return 0;
}
