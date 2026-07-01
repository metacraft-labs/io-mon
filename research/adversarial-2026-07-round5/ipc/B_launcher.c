// Launcher (out of tree): socketpair, fork peer that opens marker and passes the
// OPEN FD over SCM_RIGHTS. Then exec io-mon run -- B_client. Socket inherited.
#include "peer_common.h"
int main(int argc, char**argv){
  const char* marker=argv[1]; const char* iomon=argv[2];
  const char* depfile=argv[3]; const char* client=argv[4];
  int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  pid_t pid=fork();
  if(pid==0){
    close(sv[0]);
    int fd=open(marker, O_RDONLY);
    struct msghdr msg={0}; char c='X';
    struct iovec io={.iov_base=&c,.iov_len=1}; msg.msg_iov=&io; msg.msg_iovlen=1;
    char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf,0,sizeof cbuf);
    msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
    struct cmsghdr*cm=CMSG_FIRSTHDR(&msg);
    cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    sendmsg(sv[1], &msg, 0);
    close(sv[1]); _exit(0);
  }
  close(sv[1]);
  char fdbuf[16]; snprintf(fdbuf,sizeof fdbuf,"%d",sv[0]);
  setenv("INHERITED_FD", fdbuf, 1);
  execl(iomon, iomon, "run", "--depfile", depfile, "--", client, (char*)NULL);
  perror("execl"); return 1;
}
