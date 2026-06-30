#include <stdio.h>
#include <stdlib.h>
/* CONTRAST: ordinary fopen+fread of a marker file. io-mon MUST capture this. */
int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf)-1, f); buf[n]=0; fclose(f);
    printf("OUTPUT_DEPENDS_ON=[%s]\n", buf);
    return 0;
}
