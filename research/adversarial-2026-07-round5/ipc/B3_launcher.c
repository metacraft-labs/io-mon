// Peer reads real dependency (marker) out-of-tree, writes its content into a PIPE,
// and passes the pipe READ-END via SCM_RIGHTS. A pipe fd has no path (F_GETPATH
// fails). Client reads the pipe. Is the content-bearing read recorded/caught?
#include "peer_common.h"
int main(int argc,char**argv){
  const char* marker=argv[1]; const char* iomon=argv[2];
  const char* depfile=argv[3]; const char* client=argv[4];
  int sv[2]; socketpair(AF_UNIX,SOCK_STREAM,0,sv);
  pid_t pid=fork();
  if(pid==0){
    close(sv[0]);
    int p[2]; pipe(p);
    int src=open(marker,O_RDONLY);
    char buf[256]; ssize_t n=read(src,buf,sizeof buf); close(src);
    write(p[1],buf,n>0?n:0); close(p[1]);
    struct msghdr msg={0}; char c='X';
    struct iovec io={.iov_base=&c,.iov_len=1}; msg.msg_iov=&io; msg.msg_iovlen=1;
    char cb[CMSG_SPACE(sizeof(int))]; memset(cb,0,sizeof cb);
    msg.msg_control=cb; msg.msg_controllen=sizeof cb;
    struct cmsghdr*cm=CMSG_FIRSTHDR(&msg);
    cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm),&p[0],sizeof(int));
    sendmsg(sv[1],&msg,0); close(sv[1]); _exit(0);
  }
  close(sv[1]);
  char fb[16]; snprintf(fb,sizeof fb,"%d",sv[0]); setenv("INHERITED_FD",fb,1);
  execl(iomon,iomon,"run","--depfile",depfile,"--",client,(char*)NULL);
  perror("execl"); return 1;
}
