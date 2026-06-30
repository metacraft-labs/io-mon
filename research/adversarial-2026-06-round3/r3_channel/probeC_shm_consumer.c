// Probe C consumer (MONITORED). Opens the POSIX shm object the out-of-tree
// producer created, maps it PROT_READ, and reads the marker content. shm_open is
// NOT a path open(2); the read is a plain memory load, not read(2). Does ANY
// record name the consumed content's source?
// Build: /usr/bin/clang -o probeC_shm_consumer probeC_shm_consumer.c
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define SHM_NAME "/r3shm"
#define SHM_SIZE 4096

int main(void) {
  int fd = shm_open(SHM_NAME, O_RDONLY, 0600);
  if (fd < 0) { perror("shm_open"); return 1; }
  // Read-only shared mapping: NOT the MAP_SHARED|PROT_WRITE case io-mon records.
  void *p = mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) { perror("mmap"); return 1; }
  char buf[256];
  strncpy(buf, (const char *)p, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  fprintf(stderr, "[consumer] read from shared memory: %.60s\n", buf);
  munmap(p, SHM_SIZE);
  close(fd);
  return 0;
}
