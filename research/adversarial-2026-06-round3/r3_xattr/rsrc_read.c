#include <stdio.h>
#include <stdlib.h>
/* ATTACK: read the resource fork via the ..namedfork/rsrc path. */
int main(int argc, char** argv) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/..namedfork/rsrc", argv[1]);
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen rsrc"); return 2; }
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf)-1, f); buf[n]=0; fclose(f);
    printf("OUTPUT_DEPENDS_ON_RSRC=[%s]\n", buf);
    return 0;
}
