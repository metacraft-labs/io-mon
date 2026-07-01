// Monitored client: recvmsg to receive the passed OPEN fd, then read() the file.
// It never opened marker.txt itself.
#include "peer_common.h"
int main(void){
  int s=atoi(getenv("INHERITED_FD"));
  struct msghdr msg={0}; char c;
  struct iovec io={.iov_base=&c,.iov_len=1}; msg.msg_iov=&io; msg.msg_iovlen=1;
  char cbuf[CMSG_SPACE(sizeof(int))]; msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
  if(recvmsg(s,&msg,0)<0){perror("recvmsg");return 1;}
  struct cmsghdr*cm=CMSG_FIRSTHDR(&msg);
  int fd; memcpy(&fd, CMSG_DATA(cm), sizeof(int));
  char buf[256]; ssize_t n=read(fd, buf, sizeof buf);
  if(n>0){ write(1,"CLIENT-GOT: ",12); write(1,buf,n); }
  return 0;
}
