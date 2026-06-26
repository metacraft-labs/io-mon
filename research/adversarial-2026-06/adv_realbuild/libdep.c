/*
 * T3b probe — a NON-SYSTEM dependent dylib (the model of a toolchain's own
 * libLLVM/libclang-cpp in findings-doc break #4). A program LINKED against it
 * has dyld map it at launch via low-level kernel mmap, bypassing the hooked
 * open/openat, so before T3b it was recorded NOWHERE while io-mon recorded the
 * executable. Its value influences the program's output (a real data dependency).
 */
int dep_value(void) { return 4242; }
