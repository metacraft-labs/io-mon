#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NTHREADS 32
static char dir[512];

void* worker(void* arg){
  long id = (long)arg;
  char path[600];
  snprintf(path, sizeof path, "%s/marker_%ld.txt", dir, id);
  // small random jitter so threads interleave their reads
  FILE* f = fopen(path, "rb");
  if(!f){ fprintf(stderr,"FAIL open %s\n", path); return (void*)1; }
  char buf[64];
  size_t n = fread(buf,1,sizeof buf,f);
  (void)n;
  fclose(f);
  return NULL;
}

int main(int argc, char** argv){
  if(argc<2){ fprintf(stderr,"usage: %s <dir>\n", argv[0]); return 2; }
  snprintf(dir, sizeof dir, "%s", argv[1]);
  pthread_t th[NTHREADS];
  for(long i=0;i<NTHREADS;i++) pthread_create(&th[i], NULL, worker, (void*)i);
  for(int i=0;i<NTHREADS;i++) pthread_join(th[i], NULL);
  return 0;
}
