#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/attr.h>
#include <sys/vnode.h>
int main(int argc,char**argv){
  // argv[1] = directory to enumerate; argv[2] = name to find
  int dirfd=open(argv[1],O_RDONLY|O_DIRECTORY,0);
  if(dirfd<0){perror("open dir");return 1;}
  struct attrlist al; memset(&al,0,sizeof al);
  al.bitmapcount=ATTR_BIT_MAP_COUNT;
  al.commonattr=ATTR_CMN_RETURNED_ATTRS|ATTR_CMN_NAME;
  char buf[8192]; int found=0;
  for(;;){
    int cnt=getattrlistbulk(dirfd,&al,buf,sizeof buf,0);
    if(cnt<=0)break;
    char*p=buf;
    for(int i=0;i<cnt;i++){
      uint32_t len=*(uint32_t*)p;
      attribute_set_t*ret=(attribute_set_t*)(p+sizeof(uint32_t));
      char*field=(char*)(p+sizeof(uint32_t)+sizeof(attribute_set_t));
      if(ret->commonattr&ATTR_CMN_NAME){
        attrreference_t*nr=(attrreference_t*)field;
        char*name=((char*)nr)+nr->attr_dataoffset;
        if(argc>2 && strcmp(name,argv[2])==0){found=1;printf("FOUND:%s\n",name);}
      }
      p+=len;
    }
  }
  close(dirfd);
  return found?0:9;
}
