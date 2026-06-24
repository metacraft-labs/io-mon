// Clean internal-call proof: replace each open-family variant's entry with a
// branch to our hook; the hook records the path and does the real work via the
// raw syscall (so NO prologue relocation is needed).  Then fopen()'s
// shared-cache-internal open is observed -> proves body-patching sees internal
// callers that __interpose cannot.
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>

static int hits=0; static char last[256];

static int overwrite(void *target,void *hook){
    long pg=sysconf(_SC_PAGESIZE);
    mach_vm_address_t vb=(mach_vm_address_t)((uintptr_t)target&~(uintptr_t)(pg-1)),np=0;
    if(mach_vm_allocate(mach_task_self(),&np,pg,VM_FLAGS_ANYWHERE)) return 1;
    memcpy((void*)np,(void*)vb,pg);
    uint32_t*p=(uint32_t*)(np+((uintptr_t)target-(uintptr_t)vb));
    p[0]=0x58000050u;            // ldr x16,#8
    p[1]=0xd61f0200u;            // br x16
    *(uint64_t*)&p[2]=(uint64_t)(uintptr_t)hook;
    if(mach_vm_protect(mach_task_self(),np,pg,FALSE,VM_PROT_READ|VM_PROT_EXECUTE)) return 2;
    mach_vm_address_t dst=vb; vm_prot_t c,m;
    if(mach_vm_remap(mach_task_self(),&dst,pg,0,VM_FLAGS_OVERWRITE,mach_task_self(),np,FALSE,&c,&m,VM_INHERIT_COPY)) return 3;
    sys_icache_invalidate(target,16); return 0;
}

// Single hook for all open variants; does the real open via raw syscall.
static int hook_open(const char*path,int flags,int mode){
    hits++; if(path) strncpy(last,path,255);
    return (int)syscall(SYS_open, path, flags, mode);
}

static void inst(const char*sym){ void*t=dlsym(RTLD_DEFAULT,sym);
    if(!t){ fprintf(stderr,"  (no %s)\n",sym); return; }
    int rc=overwrite(t,(void*)hook_open); fprintf(stderr,"  hooked %-16s rc=%d @ %p\n",sym,rc,t); }

int main(void){
    fprintf(stderr,"installing open-family hooks:\n");
    inst("open"); inst("open$NOCANCEL"); inst("__open_nocancel");

    fprintf(stderr,"--- direct open ---\n");
    int b0=hits; int fd=open("/etc/hosts",O_RDONLY);
    fprintf(stderr,"  fd=%d delta=%d last=%s\n",fd,hits-b0,last); if(fd>=0) close(fd);

    fprintf(stderr,"--- fopen (shared-cache-internal) ---\n");
    int b1=hits; FILE*f=fopen("/etc/services","r");
    fprintf(stderr,"  fopen=%p delta=%d last=%s\n",(void*)f,hits-b1,last); if(f) fclose(f);

    int ok = (hits-b1)>0 && strstr(last,"services");
    fprintf(stderr,"%s\n", ok?"==> CONFIRMED: shared-cache-internal open() intercepted by body patch"
                             :"==> NOT caught via these variants");
    return ok?0:1;
}
