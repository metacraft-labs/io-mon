#include <mach/mach.h>
#include <stdio.h>
int main(void){
  host_load_info_data_t li;
  mach_msg_type_number_t cnt=HOST_LOAD_INFO_COUNT;
  host_statistics(mach_host_self(), HOST_LOAD_INFO,(host_info_t)&li,&cnt);
  FILE* f=fopen("/tmp/r5_determinism/o_hoststat.txt","w");
  fprintf(f,"load0=%u\n",li.avenrun[0]); fclose(f); return 0;
}
