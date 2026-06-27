#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
int main(int argc,char**argv){
  int n=atoi(argv[1]);
  pid_t first=0,minp=1<<30,maxp=0;
  for(int i=0;i<n;i++){
    pid_t p=fork();
    if(p==0){ _exit(0); }
    if(i==0)first=p;
    if(p<minp)minp=p; if(p>maxp)maxp=p;
    int st; waitpid(p,&st,0);
  }
  printf("forked %d children: firstpid=%d minpid=%d maxpid=%d span=%d\n",n,first,minp,maxp,maxp-minp);
  return 0;
}
