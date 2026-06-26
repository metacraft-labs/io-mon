/*
 * T3b probe — a plugin built to be loaded ONLY via dlopen (the dlopen arm of
 * findings-doc break #7). It is NOT linked by any program and is NEVER opened by
 * a libc open/stat on the test's behalf, so before T3b the file appeared in NO
 * io-mon record at all — dyld mapped it via low-level kernel mmap, bypassing the
 * hooked open/openat. Its return value influences the loader's output so the
 * dependency is real (a different plugin would change the result).
 */
int plugin_value(void) { return 0xC0DE; }
