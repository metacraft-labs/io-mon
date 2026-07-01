#include <stdio.h>
#include <sys/mount.h>
int main(int argc,char**argv){
  struct statfs s; if(statfs(argv[1],&s)){perror("statfs");return 1;}
  printf("fstype=%s mnt=%s\n",s.f_fstypename,s.f_mntonname);
  return 0;
}
