#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
extern int openbyid_np(fsid_t*, fsobj_id_t*, int);
int main(int argc,char**argv){
  struct statfs sfs; if(statfs(argv[1],&sfs)){perror("statfs");return 1;}
  struct stat st; if(stat(argv[1],&st)){perror("stat");return 1;}
  fsid_t fsid = sfs.f_fsid;
  fsobj_id_t oid; oid.fid_objno=(uint32_t)st.st_ino; oid.fid_generation=0;
  int fd=openbyid_np(&fsid,&oid,O_RDONLY);
  if(fd<0){perror("openbyid_np");return 2;}
  char buf[128]; ssize_t n=read(fd,buf,sizeof buf);
  if(n>0) write(1,buf,n);
  close(fd);
  return 0;
}
