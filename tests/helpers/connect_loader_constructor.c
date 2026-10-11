/* Genuine dlopen constructor: hold the loader lock while acquiring the same
 * real pthread mutex as a worker's first connect. No monitor callback is mocked. */
extern void capture_loader_constructor_gate(void);
__attribute__((constructor)) static void acquire_worker_mutex(void) {
  capture_loader_constructor_gate();
}
