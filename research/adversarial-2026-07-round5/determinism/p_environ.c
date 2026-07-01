#include <stdio.h>
#include <string.h>
extern char** environ;
int main(void){
  FILE* f=fopen("/tmp/r5_determinism/o_environ.txt","w");
  for(char** e=environ;*e;e++){
    if(strncmp(*e,"HOME=",5)==0){ fprintf(f,"%s\n",*e); }
  }
  fclose(f);
  return 0;
}
