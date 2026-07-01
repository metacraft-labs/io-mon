#include <mach/mach.h>
#include <stdio.h>
int main(void){
  host_basic_info_data_t bi;
  mach_msg_type_number_t cnt=HOST_BASIC_INFO_COUNT;
  host_info(mach_host_self(), HOST_BASIC_INFO,(host_info_t)&bi,&cnt);
  FILE* f=fopen("/tmp/r5_determinism/o_hostinfo.txt","w");
  fprintf(f,"ncpu=%d mem=%llu\n",bi.avail_cpus,(unsigned long long)bi.max_mem); fclose(f); return 0;
}
