/* Minimal "compiler": reads a source file (a captured file-read) and bakes a
 * NON-FILE determinism input into its output. The non-file input is selected by
 * argv[2] so argv stays structurally identical across the two runs of a mode
 * (only the environment / clock / system state differs between runs). Output is
 * always written to the SAME fixed path so the file-WRITE record is identical
 * across runs too -> the io-mon dependency set is byte-for-byte identical while
 * the produced bytes differ. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/random.h>

static void emit(const char *out_path, const char *s){
  int fd=open(out_path,O_WRONLY|O_CREAT|O_TRUNC,0644);
  write(fd,s,strlen(fd>=0?s:"")); close(fd);
}

int main(int argc,char**argv){
  const char *src=argv[1], *mode=argv[2], *out=argv[3];
  /* legitimate captured input: the source file */
  int fd=open(src,O_RDONLY); char sb[128]={0}; if(fd>=0){read(fd,sb,sizeof sb-1);close(fd);}
  char buf[512];
  if(!strcmp(mode,"env")){
    const char*e=getenv("SOURCE_DATE_EPOCH"); if(!e)e="(unset)";
    snprintf(buf,sizeof buf,"src=%.20s epoch=%s\n",sb,e);
  } else if(!strcmp(mode,"cflags")){
    const char*e=getenv("CFLAGS"); if(!e)e="(unset)";
    snprintf(buf,sizeof buf,"src=%.20s cflags=%s\n",sb,e);
  } else if(!strcmp(mode,"time")){
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    snprintf(buf,sizeof buf,"src=%.20s builtat=%ld.%09ld\n",sb,(long)ts.tv_sec,ts.tv_nsec);
  } else if(!strcmp(mode,"sysctl")){
    int n=0; size_t sz=sizeof n; sysctlbyname("hw.ncpu",&n,&sz,NULL,0);
    snprintf(buf,sizeof buf,"src=%.20s jobs=%d\n",sb,n);
  } else if(!strcmp(mode,"cwd")){
    char cwd[256]={0}; getcwd(cwd,sizeof cwd);
    snprintf(buf,sizeof buf,"src=%.20s builddir=%s\n",sb,cwd);
  } else if(!strcmp(mode,"entropy")){
    unsigned char r[4]={0}; getentropy(r,4);
    snprintf(buf,sizeof buf,"src=%.20s salt=%02x%02x%02x%02x\n",sb,r[0],r[1],r[2],r[3]);
  } else if(!strcmp(mode,"arc4")){
    snprintf(buf,sizeof buf,"src=%.20s nonce=%08x\n",sb,arc4random());
  } else if(!strcmp(mode,"uname")){
    struct utsname u; uname(&u);
    snprintf(buf,sizeof buf,"src=%.20s host=%s rel=%s\n",sb,u.nodename,u.release);
  } else { snprintf(buf,sizeof buf,"src=%.20s mode=?\n",sb); }
  emit(out,buf);
  fputs(buf,stdout);
  return 0;
}
