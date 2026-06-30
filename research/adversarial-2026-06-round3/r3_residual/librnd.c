#include <stdio.h>
#include <stdlib.h>
// A "compiler plugin"-style dylib loaded by the build tool.
// It draws entropy from arc4random and writes it into the build output.
void plugin_emit(const char* outpath){
    unsigned int r = arc4random();          // non-system caller = THIS dylib
    unsigned char buf[16];
    arc4random_buf(buf, sizeof buf);
    FILE* o = fopen(outpath, "w");
    if(!o) return;
    fprintf(o, "rand_token=%08x\n", r);
    for(int i=0;i<16;i++) fprintf(o, "%02x", buf[i]);
    fprintf(o, "\n");
    fclose(o);
}
