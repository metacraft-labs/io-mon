#include <sys/stat.h>
int main(){ struct stat st; stat("/tmp/r3_fd/marker_fstat.txt",&st); return 0; }
