#include <stdio.h>
#include <stdlib.h>
#include <sys/xattr.h>
/* ATTACK: read a marker value from an extended attribute. getxattr not hooked? */
int main(int argc, char** argv) {
    char buf[256];
    ssize_t n = getxattr(argv[1], argv[2], buf, sizeof(buf)-1, 0, 0);
    if (n < 0) { perror("getxattr"); return 2; }
    buf[n]=0;
    printf("OUTPUT_DEPENDS_ON_XATTR=[%s]\n", buf);
    return 0;
}
