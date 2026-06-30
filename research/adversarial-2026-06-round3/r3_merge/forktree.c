/* Parent forks N children CONCURRENTLY; each child reads its own distinct marker.
 * Stresses cross-process fragment merge: N+1 processes each writing fragments. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#define N 24
int main(int argc,char**argv){
  char* dir=argv[1];
  pid_t pids[N];
  for(int i=0;i<N;i++){
    pid_t p=fork();
    if(p==0){
      char path[600]; snprintf(path,sizeof path,"%s/marker_%d.txt",dir,i);
      FILE*f=fopen(path,"rb");
      if(f){ char b[64]; size_t n=fread(b,1,sizeof b,f); (void)n; fclose(f);} 
      _exit(f?0:1);
    }
    pids[i]=p;
  }
  for(int i=0;i<N;i++){ int st; waitpid(pids[i],&st,0); }
  return 0;
}
