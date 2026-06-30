// Probe C producer (OUT-OF-TREE, started separately, BEFORE the monitored run).
// Creates a POSIX shared-memory object and writes a unique marker into it. The
// object persists after this process exits (until shm_unlink), so the monitored
// consumer can map it. Content flows producer -> consumer with NO file on disk.
// Build: /usr/bin/clang -o probeC_shm_producer probeC_shm_producer.c
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define SHM_NAME "/r3shm"
#define SHM_SIZE 4096

int main(void) {
  shm_unlink(SHM_NAME); // clean slate
  int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0600);
  if (fd < 0) { perror("shm_open"); return 1; }
  if (ftruncate(fd, SHM_SIZE) < 0) { perror("ftruncate"); return 1; }
  void *p = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) { perror("mmap"); return 1; }
  const char *marker = "MARKER_SHM_CONTENT_j1k2l3 unique-shared-memory-marker";
  memcpy(p, marker, strlen(marker) + 1);
  munmap(p, SHM_SIZE);
  close(fd);
  fprintf(stderr, "[producer] wrote marker into shm %s, object persists\n", SHM_NAME);
  return 0;
}
