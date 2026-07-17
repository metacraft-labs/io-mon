#include <stdio.h>
#include "foo.h"
#include "bar.h"
int main(void){ printf("%d\n", bar(foo(20))); return 0; }
