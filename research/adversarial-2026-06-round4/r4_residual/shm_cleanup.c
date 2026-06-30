#include <sys/mman.h>
int main(int c,char**v){for(int i=1;i<c;i++)shm_unlink(v[i]);return 0;}
