#include <stdio.h>
#include <sys/xattr.h>
int main(int argc,char**argv){
  char v[128]; ssize_t n=getxattr(argv[1],"com.build.optlevel",v,sizeof(v)-1,0,0);
  if(n<0)return 1; v[n]=0;
  FILE*o=fopen(argv[2],"w"); fprintf(o,"#define OPT_LEVEL \"%s\"\n",v); fclose(o);
  return 0;
}
