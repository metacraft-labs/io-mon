/*
 * T3b probe — a program LINKED against a non-system dependent dylib
 * (libdep.dylib). dyld maps the dependent dylib at launch via low-level kernel
 * mmap (bypassing the hooked open/openat), the exact shape of findings-doc break
 * #4 where a real clang/ld64 link loaded 620 dylibs that io-mon never saw. The
 * dependency's value flows into the output, so the dylib is a genuine input.
 */
#include <stdio.h>

extern int dep_value(void);

int main(void) {
  printf("dep=%d\n", dep_value());
  return 0;
}
