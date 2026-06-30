#include <stdio.h>
extern void plugin_emit(const char*);
int main(int argc, char** argv){
    // The tool reads a deterministic input...
    FILE* f = fopen("/tmp/r3_residual/res1_dylib_entropy/src.txt","r");
    char b[64]={0}; if(f){fgets(b,64,f);fclose(f);}
    // ...then delegates output emission to the plugin dylib (which draws entropy)
    plugin_emit(argv[1]);
    printf("compiled %s", b);
    return 0;
}
