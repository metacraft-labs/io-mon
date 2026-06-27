/* Attack 3 (SCM_RIGHTS): the INPUT file is opened in a child, the fd is passed
 * to the parent over a unix socket, and the parent reads the content via mmap.
 * To io-mon the parent NEVER opened the input (no path-bearing open in the
 * consuming process), and the read goes through mmap (unhooked) -> the input is
 * invisible in the process that actually consumes it. (Models a build worker
 * that receives fds from a coordinating daemon.) */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int recv_fd(int sock){
  struct msghdr msg; memset(&msg,0,sizeof msg);
  char cbuf[CMSG_SPACE(sizeof(int))]; char dummy;
  struct iovec io={&dummy,1};
  msg.msg_iov=&io; msg.msg_iovlen=1; msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
  if(recvmsg(sock,&msg,0)<0) return -1;
  struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
  int fd; memcpy(&fd,CMSG_DATA(c),sizeof fd); return fd;
}
static void send_fd(int sock,int fd){
  struct msghdr msg; memset(&msg,0,sizeof msg);
  char cbuf[CMSG_SPACE(sizeof(int))]; char dummy='x';
  struct iovec io={&dummy,1};
  msg.msg_iov=&io; msg.msg_iovlen=1; msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
  struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
  c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c),&fd,sizeof fd);
  sendmsg(sock,&msg,0);
}
int main(){
  int sv[2]; socketpair(AF_UNIX,SOCK_STREAM,0,sv);
  pid_t pid=fork();
  if(pid==0){ /* child: the only one that open()s the input */
    close(sv[0]);
    int fd=open("/tmp/r2_mmap/passed_input.dat",O_RDONLY);
    send_fd(sv[1],fd); _exit(0);
  }
  /* parent: consumes content via mmap on a received fd, no open of the path */
  close(sv[1]);
  int fd=recv_fd(sv[0]);
  struct stat st; fstat(fd,&st);
  char *m=mmap(0,st.st_size,PROT_READ,MAP_SHARED,fd,0);
  long sum=0; for(off_t i=0;i<st.st_size;i++) sum+=(unsigned char)m[i];
  munmap(m,st.st_size); close(fd);
  int fo=open("/tmp/r2_mmap/scm_derived_out.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  char b[64]; int n=snprintf(b,sizeof b,"scm_sum=%ld\n",sum); write(fo,b,n); close(fo);
  return 0;
}
