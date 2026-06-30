#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
extern char**environ;
// argv[1]=mode-for-child, argv[2]=marker path, argv[3]=spawn-style
// spawn-style: plain | fileaction | suspended | cloexecdefault | setsid
int main(int argc,char**argv){
  const char* childmode = argv[1];
  const char* marker = argv[2];
  const char* style = argc>3?argv[3]:"plain";
  posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
  posix_spawnattr_t at; posix_spawnattr_init(&at);
  char* cargv[5]; cargv[0]="/tmp/r4_proc/child"; cargv[1]=(char*)marker; cargv[2]=(char*)childmode; cargv[3]=NULL; cargv[4]=NULL;
  int use_fa=0;
  if(!strcmp(style,"fileaction")){
    // open the marker IN THE CHILD via file-actions onto fd 7; child reads fd 7
    posix_spawn_file_actions_addopen(&fa, 7, marker, O_RDONLY, 0);
    cargv[3]="7"; use_fa=1;
  } else if(!strcmp(style,"suspended")){
    posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED);
  } else if(!strcmp(style,"cloexecdefault")){
    #ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT);
    #endif
  } else if(!strcmp(style,"setsigdef")){
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK);
    sigset_t s; sigemptyset(&s); posix_spawnattr_setsigdefault(&at,&s); posix_spawnattr_setsigmask(&at,&s);
  }
  pid_t pid;
  int rc = posix_spawn(&pid, cargv[0], use_fa?&fa:NULL, &at, cargv, environ);
  if(rc!=0){ fprintf(stderr,"spawn failed %d\n",rc); return 1; }
  if(!strcmp(style,"suspended")){ kill(pid, SIGCONT); }
  int st; waitpid(pid,&st,0);
  return 0;
}
