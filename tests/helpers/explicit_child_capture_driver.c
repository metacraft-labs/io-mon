/* Real process fixture for the explicit-env inheritance boundary. Its child
 * reads only the requested genuine input; no capture records are synthesized.
 * The owning Nim public runMonitored driver supplies/observes the actual shim. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static char *entry(const char *name,const char *value) {
  size_t n=strlen(name)+strlen(value)+2;char *p=malloc(n);
  if(!p)exit(70);snprintf(p,n,"%s=%s",name,value);return p;
}
int main(int argc,char **argv) {
  if(argc==4 && strcmp(argv[1],"read")==0) {
    const char *generation=getenv("REPRO_MONITOR_EXEC_GEN");
    if((generation?strtol(generation,NULL,10):0)!=strtol(argv[3],NULL,10))return 4;
    char c;int f=open(argv[2],O_RDONLY);if(f<0)return 2;
    int ok=read(f,&c,1)==1;close(f);return ok?0:3;
  }
  if(argc!=5)return 64;
  const char *operation=argv[1],*mode=argv[2];char *env[20]={0};int n=0;
  const char *image=argv[3];
  char *fixturePath=NULL;
  if(strcmp(operation,"spawnp-search")==0) {
    const char *slash=strrchr(image,'/');if(!slash)return 67;
    size_t prefix=(size_t)(slash-image);const char *oldPath=getenv("PATH");
    size_t size=prefix+strlen(oldPath?oldPath:"")+2;
    fixturePath=malloc(size);if(!fixturePath)return 70;
    snprintf(fixturePath,size,"%.*s:%s",(int)prefix,image,oldPath?oldPath:"");
    image=slash+1;
  }
  env[n++]=entry("PATH",fixturePath?fixturePath:(getenv("PATH")?getenv("PATH"):""));
  if(fixturePath && setenv("PATH",fixturePath,1)!=0)return 68;
  free(fixturePath);
  const char *names[]={"REPRO_MONITOR_FRAGMENT_DIR","REPRO_MONITOR_SESSION",
    "REPRO_MONITOR_SHIM_LIB","REPRO_MONITOR_INTEREST",
    "REPRO_MONITOR_EVIDENCE","REPRO_MONITOR_DEP_SHM"};
  if(strcmp(mode,"complete")==0) {
    for(size_t i=0;i<6;i++)if(getenv(names[i]))env[n++]=entry(names[i],getenv(names[i]));
  } else if(strcmp(mode,"partial")==0) {
    env[n++]=entry(names[1],getenv(names[1])?getenv(names[1]):"partial");
  } else if(strcmp(mode,"duplicate")==0) {
    env[n++]=entry(names[1],"one");env[n++]=entry(names[1],"two");
  } else if(strcmp(mode,"malformed")==0) {
    env[n++]=entry(names[0],getenv(names[0])?getenv(names[0]):".");
    env[n++]=entry(names[1],"contains whitespace");
  } else if(strcmp(mode,"preloaded")==0) {
    env[n++]=entry("LD_PRELOAD",getenv("REPRO_MONITOR_SHIM_LIB")?getenv("REPRO_MONITOR_SHIM_LIB"):"");
  } else if(strcmp(mode,"foreign-seed")==0) {
    env[n++]=entry("REPRO_MONITOR_SHIM_LIB","/missing-foreign-shim.so");
  } else if(strcmp(mode,"missing")!=0)return 65;
  char *childargv[]={argv[3],"read",argv[4],strcmp(operation,"exec")==0?"1":"0",NULL};
  if(strcmp(operation,"exec")==0) {execve(argv[3],childargv,env);return 71;}
  if(strcmp(operation,"exec-failure")==0) {
    errno=0;int r=execve("/io-mon-explicit-child-no-such-image",childargv,env);
    int saved=errno;for(int i=0;i<n;i++)free(env[i]);return r==-1&&saved==ENOENT?0:72;
  }
  pid_t pid=0;int code;
  if(strcmp(operation,"spawn")==0)code=posix_spawn(&pid,argv[3],NULL,NULL,childargv,env);
  else if(strcmp(operation,"spawnp")==0 || strcmp(operation,"spawnp-search")==0)code=posix_spawnp(&pid,image,NULL,NULL,childargv,env);
  else if(strcmp(operation,"spawn-failure")==0)code=posix_spawn(&pid,"/io-mon-explicit-child-no-such-image",NULL,NULL,childargv,env);
  else if(strcmp(operation,"spawnp-failure")==0)code=posix_spawnp(&pid,"io-mon-explicit-child-no-such-image",NULL,NULL,childargv,env);
  else return 66;
  for(int i=0;i<n;i++)free(env[i]);
  if(strstr(operation,"failure"))return code==ENOENT?0:73;
  if(code!=0)return 74;int status;if(waitpid(pid,&status,0)!=pid)return 75;
  return WIFEXITED(status)?WEXITSTATUS(status):76;
}
