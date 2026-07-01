// Monitored client: receives an OPEN regular-file fd (opened out-of-tree) via
// SCM_RIGHTS, then consumes its content via mmap -- NO read() syscall. If io-mon
// resolves passed-fd paths only at read() time, this bypasses it entirely.
#include "peer_common.h"
#include <sys/mman.h>
#include <sys/stat.h>
int main(void){
  int s=atoi(getenv("INHERITED_FD"));
  struct msghdr msg={0}; char c;
  struct iovec io={.iov_base=&c,.iov_len=1}; msg.msg_iov=&io; msg.msg_iovlen=1;
  char cb[CMSG_SPACE(sizeof(int))]; msg.msg_control=cb; msg.msg_controllen=sizeof cb;
  if(recvmsg(s,&msg,0)<0){perror("recvmsg");return 1;}
  struct cmsghdr*cm=CMSG_FIRSTHDR(&msg);
  int fd; memcpy(&fd,CMSG_DATA(cm),sizeof(int));
  struct stat st; fstat(fd,&st);
  size_t len = st.st_size>0? (size_t)st.st_size : 64;
  void* p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if(p==MAP_FAILED){perror("mmap");return 1;}
  write(1,"CLIENT-MMAP: ",13); write(1,p,len);
  return 0;
}
