// Can we OVERWRITE the mapping at an existing code VA with our own modified
// executable page (the Dobby/substrate arm64 technique), in-process, under
// SIP?  Two sub-tests: own __TEXT and shared-cache getpid.  Each forked.
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>

static void out(const char*s){write(1,s,strlen(s));}
static void hx(const char*l,unsigned long long v){out(l);char b[18];b[0]='0';b[1]='x';for(int i=0;i<14;i++){int n=(v>>((13-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[16]='\n';b[17]=0;write(1,b,16);}
__attribute__((noinline)) int victim(void){ return 7; }

static void cell(void *target){
    long pg=sysconf(_SC_PAGESIZE);
    mach_vm_address_t vbase=(mach_vm_address_t)((uintptr_t)target & ~(uintptr_t)(pg-1));
    // 1) allocate a fresh page, copy original, patch prologue to movz w0,#0x1234; ret
    mach_vm_address_t newp=0;
    kern_return_t kr=mach_vm_allocate(mach_task_self(),&newp,pg,VM_FLAGS_ANYWHERE);
    hx("  vm_allocate kr=",(unsigned)kr); if(kr) _exit(20);
    memcpy((void*)newp,(void*)vbase,pg);
    uint32_t *off=(uint32_t*)(newp + ((uintptr_t)target-(uintptr_t)vbase));
    off[0]=0x52824680u; off[1]=0xd65f03c0u;
    // 2) make the fresh page executable (needs allow-unsigned-executable-memory)
    kr=mach_vm_protect(mach_task_self(),newp,pg,FALSE,VM_PROT_READ|VM_PROT_EXECUTE);
    hx("  protect new RX kr=",(unsigned)kr); if(kr) _exit(21);
    // 3) overwrite the mapping at the original VA with the fresh page
    mach_vm_address_t dst=vbase; vm_prot_t cur=0,max=0;
    kr=mach_vm_remap(mach_task_self(),&dst,pg,0,VM_FLAGS_OVERWRITE,
                     mach_task_self(),newp,FALSE,&cur,&max,VM_INHERIT_COPY);
    hx("  vm_remap OVERWRITE kr=",(unsigned)kr); if(kr) _exit(22);
    sys_icache_invalidate(target,8);
    out("  calling target...\n");
    int (*f)(void)=(int(*)(void))target;
    int r=f();
    hx("  result=",(unsigned)r);
    _exit(r==0x1234?0:11);
}

static void run(const char*n,void*t){
    out("== "); out(n); out(" ==\n");
    pid_t pid=fork(); if(pid==0){ cell(t); _exit(99); }
    int st; waitpid(pid,&st,0);
    if(WIFSIGNALED(st)){ int s=WTERMSIG(st); char b[3]; b[0]='0'+s/10;b[1]='0'+s%10;b[2]='\n'; out("  -> CRASH signal="); write(1,b,3); }
    else { int e=WEXITSTATUS(st); out(e==0?"  -> PASS: remapped & executed patched code\n":"  -> FAIL exit\n"); hx("     exit=",(unsigned)e); }
}

int main(void){
    void*gp=dlsym(RTLD_DEFAULT,"getpid");
    run("own __TEXT remap", (void*)victim);
    run("shared-cache remap", gp);
    return 0;
}
