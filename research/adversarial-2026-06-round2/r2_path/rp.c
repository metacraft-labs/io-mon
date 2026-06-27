#include <stdlib.h>
#include <stdio.h>
int main(int c,char**v){char b[1024];for(int i=1;i<c;i++){if(realpath(v[i],b))printf("realpath('%s') = '%s'\n",v[i],b);else printf("realpath('%s') FAILED\n",v[i]);}return 0;}
