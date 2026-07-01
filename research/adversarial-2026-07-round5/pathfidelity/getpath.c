#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(int c,char**v){int fd=open(v[1],O_RDONLY);char p[1024];
 if(fd<0){perror("open");return 1;}
 fcntl(fd,F_GETPATH,p); printf("F_GETPATH=%s\n",p);
#ifdef F_GETPATH_NOFIRMLINK
 char q[1024]; fcntl(fd,F_GETPATH_NOFIRMLINK,q); printf("F_GETPATH_NOFIRMLINK=%s\n",q);
#endif
 struct stat st; fstat(fd,&st); printf("dev=%d ino=%llu\n",st.st_dev,(unsigned long long)st.st_ino);
 close(fd); return 0;}
