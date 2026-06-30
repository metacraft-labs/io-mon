#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
int main(void){
    // Negative-existence dependency: behave differently if "maybe.h" is absent.
    if (access("maybe.h", F_OK) == 0) {
        printf("PRESENT: using maybe.h config\n");
    } else {
        printf("ABSENT: using defaults\n");
    }
    return 0;
}
