#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
typedef uint64_t guardid_t;
extern int guarded_open_np(const char*, const guardid_t*, unsigned, int, ...);
int main(){
  const char *db="/tmp/r2_mmap/database_input.db";
  guardid_t g=0x1234;
  unsigned flagsets[]={2u,1u,3u,4u};
  int fd=-1;
  for(int i=0;i<4;i++){ fd=guarded_open_np(db,&g,flagsets[i],O_RDONLY); fprintf(stderr,"gf=%u fd=%d errno=%d\n",flagsets[i],fd,errno); if(fd>=0) break; }
  if(fd<0) return 1;
  struct stat st; fstat(fd,&st);
  char *m=mmap(0,st.st_size,PROT_READ,MAP_SHARED,fd,0);
  long sum=0; for(off_t i=0;i<st.st_size;i++) sum+=(unsigned char)m[i];
  munmap(m,st.st_size); close(fd);
  int fo=open("/tmp/r2_mmap/db_derived_out.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  char b[64]; int n=snprintf(b,sizeof b,"db_sum=%ld\n",sum); write(fo,b,n); close(fo);
  return 0;
}
