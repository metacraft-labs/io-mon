#include <stdio.h>
#include <string.h>
#include <crt_externs.h>
int main(void){
  char*** ep=_NSGetEnviron();
  FILE* f=fopen("/tmp/r5_determinism/o_nsenv.txt","w");
  for(char** e=*ep;*e;e++){ if(strncmp(*e,"PATH=",5)==0) fprintf(f,"%s\n",*e);}
  fclose(f); return 0;
}
