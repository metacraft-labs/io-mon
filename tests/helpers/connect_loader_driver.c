/* Isolate the real loader/library-mutex ordering seen in LTTng startup.
 * The worker performs a genuine AF_UNIX connect through the selected monitor;
 * a bounded fixture alarm makes a loader deadlock fail, never pass silently.
 * Original test and RunQuota policies are not changed by this child fixture. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static pthread_mutex_t library_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_int worker_ready, constructor_entered;
static const char *socket_path;
static int connected;

void capture_loader_constructor_gate(void) {
  atomic_store(&constructor_entered, 1);
  if (pthread_mutex_lock(&library_mutex) != 0) abort();
  if (pthread_mutex_unlock(&library_mutex) != 0) abort();
}

static void *worker(void *unused) {
  (void)unused;
  if (pthread_mutex_lock(&library_mutex) != 0) abort();
  atomic_store(&worker_ready, 1);
  while (!atomic_load(&constructor_entered)) sched_yield();
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  if (fd < 0 || strlen(socket_path) >= sizeof(address.sun_path)) abort();
  strcpy(address.sun_path, socket_path);
  connected = connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0;
  close(fd);
  if (pthread_mutex_unlock(&library_mutex) != 0) abort();
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 4) return 64;
  socket_path = argv[3];
  alarm(20);
  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  if (server < 0 || strlen(socket_path) >= sizeof(address.sun_path)) return 65;
  strcpy(address.sun_path, socket_path);
  if (bind(server, (const struct sockaddr *)&address, sizeof(address)) || listen(server, 1)) return 66;
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL)) return 67;
  while (!atomic_load(&worker_ready)) sched_yield();
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!library) { fprintf(stderr, "%s\n", dlerror()); return 68; }
  if (pthread_join(thread, NULL) || !connected || !atomic_load(&constructor_entered)) return 69;
  int input = open(argv[2], O_RDONLY);
  char bytes[64];
  if (input < 0 || read(input, bytes, sizeof(bytes)) <= 0) return 70;
  close(input);dlclose(library);close(server);unlink(socket_path);alarm(0);
  puts("actual loader constructor and worker connect completed");
  return 0;
}
