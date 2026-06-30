// Probe F: fcopyfile(3) with COPYFILE_DATA (NOT a clone) between two fds. This is
// a real byte copy fd->fd. io-mon's fcopyfile hook only emits a content record
// when the CLONE flag is set; COPYFILE_DATA falls outside that branch. Question:
// is the SOURCE content recorded as a read, or only as the open?
// Build: /usr/bin/clang -o probeF_fcopyfile_data probeF_fcopyfile_data.c
#include <copyfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
  const char *src = argc > 1 ? argv[1] : "/tmp/r3_channel/markerF.txt";
  const char *dst = argc > 2 ? argv[2] : "/tmp/r3_channel/markerF.out";
  int sfd = open(src, O_RDONLY);                       // captured: moFileOpen(src)
  if (sfd < 0) { perror("open src"); return 1; }
  int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dfd < 0) { perror("open dst"); return 1; }
  // COPYFILE_DATA: copy the bytes. No CLONE flag.
  if (fcopyfile(sfd, dfd, NULL, COPYFILE_DATA) != 0) { perror("fcopyfile"); return 1; }
  fprintf(stderr, "[probeF] fcopyfile COPYFILE_DATA copied %s -> %s\n", src, dst);
  close(sfd); close(dfd);
  return 0;
}
