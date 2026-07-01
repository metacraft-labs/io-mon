#include <time.h>
#include <stdio.h>
int main(void){
  time_t t=0; // fixed input so only TZ file matters
  struct tm* lt=localtime(&t);
  FILE* f=fopen("/tmp/r5_determinism/o_localtime.txt","w");
  fprintf(f,"gmtoff=%ld zone=%s\n",lt->tm_gmtoff,lt->tm_zone); fclose(f); return 0;
}
