#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
// A codegen tool that bakes the wall clock into its output, __DATE__/__TIME__ style.
int main(int argc, char** argv){
    // deterministic input
    FILE* f = fopen("/tmp/r3_residual/res2_time/template.txt","r");
    char b[128]={0}; if(f){fread(b,1,127,f);fclose(b?f:NULL);}
    struct timeval tv; gettimeofday(&tv,NULL);
    time_t t = time(NULL);
    FILE* o = fopen(argv[1],"w");
    if(o){
        fprintf(o,"/* generated header */\n");
        fprintf(o,"#define BUILD_UNIX %ld\n",(long)t);
        fprintf(o,"#define BUILD_USEC %ld\n",(long)tv.tv_usec);
        fclose(o);
    }
    return 0;
}
