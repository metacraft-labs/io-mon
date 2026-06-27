/* Monitored top process. posix_spawns an UN-INJECTABLE SIP system binary
 * (/usr/bin/cat) to read a marker. The system binary strips DYLD_INSERT, so
 * it emits NO process-start; only the parent's mrProcessSpawn(childOsPid=catpid)
 * is recorded. Baseline: catpid has no process-start -> downgrade -> mcIncomplete. */
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc,char**argv){
  char *args[] = {"/usr/bin/cat", argv[1], NULL};
  pid_t pid=0;
  int rc=posix_spawn(&pid,"/usr/bin/cat",NULL,NULL,args,environ);
  if(rc!=0){ printf("spawn failed %d\n",rc); return 1; }
  int st; waitpid(pid,&st,0);
  printf("SPAWNER: cat ran as pid=%d\n",(int)pid);
  return 0;
}
