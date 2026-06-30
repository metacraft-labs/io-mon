#include <stdlib.h>
unsigned draw_entropy(void){ return arc4random(); }  /* non-system dylib draws entropy */
