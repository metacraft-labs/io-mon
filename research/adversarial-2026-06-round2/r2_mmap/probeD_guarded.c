/* Attack 3: open via a NON-hooked open variant (guarded_open_np, the syscall
 * sqlite/dyld use), then read the file CONTENT via mmap. Neither the open nor
 * the read passes a hooked entry point -> the input file is fully invisible. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
typedef uint64_t guardid_t;
extern int guarded_open_np(const char*, const guardid_t*, unsigned, int, ...);
#define GUARD_CLOSE (1u<<0)
#define GUARD_DUP   (1u<<1)
int main(){
  const char *db = "/tmp/r2_mmap/database_input.db";
  guardid_t g = 0x1234;
  int fd = guarded_open_np(db, &g, GUARD_CLOSE|GUARD_DUP, O_RDONLY);
  if(fd<0){perror("guarded_open_np");return 1;}
  struct stat st; fstat(fd,&st);
  char *m = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  long sum=0; for(off_t i=0;i<st.st_size;i++) sum+=(unsigned char)m[i];
  munmap(m,st.st_size); close(fd);
  int fo=open("/tmp/r2_mmap/db_derived_out.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  char b[64]; int n=snprintf(b,sizeof b,"db_sum=%ld\n",sum); write(fo,b,n); close(fo);
  return 0;
}
