// Full matrix: which in-process technique (if any) can make an existing
// code-signed executable page writable, modify it, and execute it, on
// macOS 26 / Apple Silicon under SIP?  Each cell runs in a forked child so a
// crash (SIGBUS/SIGKILL) only kills that cell; the parent reports the signal.
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>

static void out(const char*s){write(1,s,strlen(s));}
static void hx(const char*l,unsigned long long v){out(l);char b[18];b[0]='0';b[1]='x';for(int i=0;i<14;i++){int n=(v>>((13-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[16]='\n';b[17]=0;write(1,b,16);}

__attribute__((noinline)) int victim(void){ return 7; }

enum Method { MPROTECT, VMP, VMP_COPY };

// Runs in child. Returns via _exit: 0=full success(executed patch), 10=protect failed gracefully(rc!=0), 11=wrote ok but exec wrong. Crash => signal.
static void cell(void *p, enum Method m){
    uint32_t *code=(uint32_t*)p;
    long pg=sysconf(_SC_PAGESIZE);
    uintptr_t base=(uintptr_t)code&~(uintptr_t)(pg-1);
    int rc;
    if(m==MPROTECT){ rc=mprotect((void*)base,pg*2,PROT_READ|PROT_WRITE); }
    else { kern_return_t kr=vm_protect(mach_task_self(),(vm_address_t)base,pg*2,FALSE,
              VM_PROT_READ|VM_PROT_WRITE|(m==VMP_COPY?VM_PROT_COPY:0)); rc=(int)kr; }
    hx("    protect rc=",(unsigned)rc);
    if(rc!=0){ _exit(10); }
    // write
    code[0]=0x52824680u; code[1]=0xd65f03c0u; // movz w0,#0x1234 ; ret
    out("    wrote ok\n");
    // back to RX
    if(m==MPROTECT) mprotect((void*)base,pg*2,PROT_READ|PROT_EXEC);
    else vm_protect(mach_task_self(),(vm_address_t)base,pg*2,FALSE,VM_PROT_READ|VM_PROT_EXECUTE);
    sys_icache_invalidate(p,8);
    int (*f)(void)=(int(*)(void))p;
    int r=f();
    _exit(r==0x1234?0:11);
}

static void run(const char*name, void*p, enum Method m){
    out("== "); out(name); out(" ==\n");
    pid_t pid=fork();
    if(pid==0){ cell(p,m); _exit(99); }
    int st; waitpid(pid,&st,0);
    if(WIFSIGNALED(st)){ out("    -> CRASH signal="); char b[4]; int s=WTERMSIG(st); b[0]='0'+s/10; b[1]='0'+s%10; b[2]='\n'; b[3]=0; write(1,b,3);
        out(s==10?"       (SIGBUS — protection/CS fault)\n":s==9?"       (SIGKILL — uncatchable, likely AMFI/CS kill)\n":"\n"); }
    else { int e=WEXITSTATUS(st);
        out(e==0?"    -> PASS: patched & executed\n": e==10?"    -> protect refused gracefully (rc!=0)\n": e==11?"    -> wrote but exec wrong\n":"    -> other\n"); }
}

int main(void){
    void *gp=dlsym(RTLD_DEFAULT,"getpid");
    hx("own victim @ ",(uintptr_t)victim);
    hx("shared getpid @ ",(uintptr_t)gp);
    out("\n--- OWN __TEXT (this binary) ---\n");
    run("own  mprotect",      (void*)victim, MPROTECT);
    run("own  vm_protect",    (void*)victim, VMP);
    run("own  vm_protect+COPY",(void*)victim, VMP_COPY);
    out("\n--- SHARED CACHE (libsystem getpid) ---\n");
    run("dsc  mprotect",      gp, MPROTECT);
    run("dsc  vm_protect",    gp, VMP);
    run("dsc  vm_protect+COPY",gp, VMP_COPY);
    return 0;
}
