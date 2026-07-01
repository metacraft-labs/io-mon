/* Multi-op prober. Each arg is "op:path". ops: stat, lstat, access, open, chdir.
 * chdir changes cwd for subsequent relative ops. Exercises path-probe (no fd)
 * records for BOTH existent and non-existent targets. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(int argc,char**argv){
  for(int i=1;i<argc;i++){
    char *c=strchr(argv[i],':'); if(!c){fprintf(stderr,"bad %s\n",argv[i]);continue;}
    *c=0; char*op=argv[i]; char*p=c+1; struct stat st; int r=-1;
    if(!strcmp(op,"stat")) r=stat(p,&st);
    else if(!strcmp(op,"lstat")) r=lstat(p,&st);
    else if(!strcmp(op,"access")) r=access(p,F_OK);
    else if(!strcmp(op,"open")){int fd=open(p,O_RDONLY); r=fd; if(fd>=0)close(fd);}
    else if(!strcmp(op,"chdir")){r=chdir(p);}
    fprintf(stderr,"%s(%s)=%d\n",op,p,r);
  }
  return 0;
}
