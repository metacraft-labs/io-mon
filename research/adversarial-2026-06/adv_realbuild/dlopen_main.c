/*
 * T3b probe — runtime dlopen of a plugin that is NOT otherwise opened (the
 * dlopen arm of findings-doc break #7). dlopen("./plugin.dylib") maps the plugin
 * via dyld's low-level kernel mmap, bypassing the hooked open/openat, so before
 * T3b plugin.dylib was recorded NOWHERE. The plugin's value influences the
 * output, making the dependency genuine. Run from the directory that holds
 * plugin.dylib (the test sets the child's workingDir). Exits non-zero on any
 * failure so the harness fails loudly.
 */
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
  void *h = dlopen("./plugin.dylib", RTLD_NOW | RTLD_LOCAL);
  if (h == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  int (*plugin_value)(void) = (int (*)(void))dlsym(h, "plugin_value");
  if (plugin_value == NULL) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror());
    return 3;
  }
  printf("plugin=%d\n", plugin_value());
  return 0;
}
