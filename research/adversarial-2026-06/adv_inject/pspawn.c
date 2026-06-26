#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char**environ;
// build an envp from environ but with DYLD_INSERT_LIBRARIES forced empty (present-but-empty)
static char** env_emptydyld(void){
  size_t n=0; while(environ[n])n++;
  char**e=calloc(n+2,sizeof(char*)); size_t j=0; int put=0;
  for(size_t i=0;i<n;i++){
    if(strncmp(environ[i],"DYLD_INSERT_LIBRARIES=",22)==0){ e[j++]="DYLD_INSERT_LIBRARIES="; put=1; }
    else e[j++]=environ[i];
  }
  if(!put) e[j++]="DYLD_INSERT_LIBRARIES=";
  e[j]=NULL; return e;
}
static char** env_scrub(void){ // drop DYLD_* and CT_SANDBOX_TOOLS_DIR entirely
  size_t n=0; while(environ[n])n++;
  char**e=calloc(n+1,sizeof(char*)); size_t j=0;
  for(size_t i=0;i<n;i++){
    if(strncmp(environ[i],"DYLD_",5)==0) continue;
    if(strncmp(environ[i],"CT_SANDBOX_TOOLS_DIR=",21)==0) continue;
    e[j++]=environ[i];
  }
  e[j]=NULL; return e;
}
int main(int argc,char**argv){
  if(argc<5){fprintf(stderr,"usage: pspawn setexec env prog marker\n");return 2;}
  int setexec=atoi(argv[1]);
  const char*envmode=argv[2];
  char*prog=argv[3]; char*marker=argv[4];
  char**envp = environ;
  if(strcmp(envmode,"emptydyld")==0) envp=env_emptydyld();
  else if(strcmp(envmode,"scrub")==0) envp=env_scrub();
  posix_spawnattr_t attr; posix_spawnattr_init(&attr);
  short flags=0;
  if(setexec) flags|=POSIX_SPAWN_SETEXEC;
  posix_spawnattr_setflags(&attr,flags);
  char*child[]={prog,marker,NULL};
  pid_t pid;
  printf("[pspawn] setexec=%d env=%s prog=%s pid=%d\n",setexec,envmode,prog,(int)getpid());
  fflush(stdout);
  int rc=posix_spawn(&pid,prog,NULL,&attr,child,envp);
  // with SETEXEC, we never get here on success
  if(rc){fprintf(stderr,"[pspawn] spawn rc=%d (%s)\n",rc,strerror(rc));return 1;}
  int st; waitpid(pid,&st,0);
  printf("[pspawn] child exited status=%d\n",WEXITSTATUS(st));
  return 0;
}
