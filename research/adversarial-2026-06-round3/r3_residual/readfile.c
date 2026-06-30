#include <stdio.h>
int main(int argc,char**argv){FILE*f=fopen(argv[1],"r");char b[128];if(f){size_t n=fread(b,1,127,f);fwrite(b,1,n,stdout);fclose(f);}return 0;}
