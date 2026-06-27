#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>
int main(int argc,char**argv){
  long n=atol(argv[1]);
  pid_t prev=0, first=0; int wraps=0; pid_t wrapto=0;
  struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
  for(long i=0;i<n;i++){
    pid_t p=fork();
    if(p==0)_exit(0);
    if(i==0)first=p;
    if(prev && p < prev-1000){ wraps++; if(wraps==1) wrapto=p; }
    prev=p;
    int st; waitpid(p,&st,0);
  }
  clock_gettime(CLOCK_MONOTONIC,&t1);
  double sec=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
  printf("n=%ld first=%d last=%d wraps=%d wrapto=%d %.2fs (%.0f forks/s)\n",
    n,first,prev,wraps,wrapto,sec,n/sec);
  return 0;
}
