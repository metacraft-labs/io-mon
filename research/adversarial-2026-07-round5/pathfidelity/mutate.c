/* RW2 mutations against absent/relative/firmlink targets. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
int main(int argc,char**argv){
  for(int i=1;i<argc;i++){
    char*c=strchr(argv[i],':'); *c=0; char*op=argv[i]; char*p=c+1; int r=-1;
    if(!strcmp(op,"unlink")) r=unlink(p);
    else if(!strcmp(op,"mkdir")) r=mkdir(p,0755);
    else if(!strcmp(op,"rmdir")) r=rmdir(p);
    fprintf(stderr,"%s(%s)=%d\n",op,p,r);
  }
  return 0;
}
