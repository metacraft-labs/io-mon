#include <dirent.h>
#include <stdio.h>
int main(int c,char**v){DIR*d=opendir(v[1]);struct dirent*e;int n=0,k=0;
while((e=readdir(d))){n++;if(!__builtin_strcmp(e->d_name,"__init__.py"))k=1;}
printf("entries=%d saw__init__=%d\n",n,k);return 0;}
