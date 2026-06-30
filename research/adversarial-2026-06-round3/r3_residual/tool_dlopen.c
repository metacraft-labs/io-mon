#include <stdio.h>
#include <dlfcn.h>
int main(int argc,char**argv){
    // Real-world "compiler pass-plugin loaded at runtime" case.
    void*h=dlopen("/tmp/r3_residual/res1_dylib_entropy/librnd.dylib",RTLD_NOW);
    if(!h){fprintf(stderr,"dlopen: %s\n",dlerror());return 1;}
    void(*emit)(const char*)=(void(*)(const char*))dlsym(h,"plugin_emit");
    if(!emit){fprintf(stderr,"dlsym fail\n");return 1;}
    emit(argv[1]);   // entropy drawn inside the dlopen'd plugin
    printf("dlopen-plugin emitted %s\n",argv[1]);
    return 0;
}
