#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv){
    unsigned int r = arc4random();          // caller = MAIN EXE __TEXT
    FILE* o = fopen(argv[1], "w");
    if(o){ fprintf(o,"rand=%08x\n", r); fclose(o);}
    return 0;
}
