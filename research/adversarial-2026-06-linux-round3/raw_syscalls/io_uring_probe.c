#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if __has_include(<liburing.h>)
#include <liburing.h>
#define HAVE_LIBURING 1
#else
#define HAVE_LIBURING 0
#endif

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }
#if !HAVE_LIBURING
  fprintf(stderr, "liburing headers unavailable; skipping io_uring probe\n");
  return 77;
#else
  struct io_uring ring;
  int rc = io_uring_queue_init(8, &ring, 0);
  if (rc < 0) {
    fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-rc));
    return 77;
  }

  struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  io_uring_prep_openat(sqe, AT_FDCWD, argv[1], O_RDONLY | O_CLOEXEC, 0);
  io_uring_sqe_set_data(sqe, (void *)1);
  rc = io_uring_submit(&ring);
  if (rc < 0) {
    fprintf(stderr, "io_uring_submit openat: %s\n", strerror(-rc));
    io_uring_queue_exit(&ring);
    return 77;
  }
  struct io_uring_cqe *cqe;
  rc = io_uring_wait_cqe(&ring, &cqe);
  if (rc < 0) {
    fprintf(stderr, "io_uring_wait_cqe openat: %s\n", strerror(-rc));
    io_uring_queue_exit(&ring);
    return 77;
  }
  int fd = cqe->res;
  io_uring_cqe_seen(&ring, cqe);
  if (fd < 0) {
    fprintf(stderr, "io_uring openat result: %s\n", strerror(-fd));
    io_uring_queue_exit(&ring);
    return 1;
  }

  char buf[4096];
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_read(sqe, fd, buf, sizeof buf, 0);
  rc = io_uring_submit(&ring);
  if (rc < 0) {
    fprintf(stderr, "io_uring_submit read: %s\n", strerror(-rc));
    close(fd);
    io_uring_queue_exit(&ring);
    return 77;
  }
  rc = io_uring_wait_cqe(&ring, &cqe);
  if (rc < 0) {
    fprintf(stderr, "io_uring_wait_cqe read: %s\n", strerror(-rc));
    close(fd);
    io_uring_queue_exit(&ring);
    return 77;
  }
  int n = cqe->res;
  io_uring_cqe_seen(&ring, cqe);

  unsigned long long sum = 0;
  if (n > 0) {
    for (int i = 0; i < n; i++) sum += (unsigned char)buf[i];
  }
  close(fd);
  io_uring_queue_exit(&ring);
  if (n < 0) {
    fprintf(stderr, "io_uring read result: %s\n", strerror(-n));
    return 1;
  }
  printf("io_uring_probe bytes=%d sum=%llu\n", n, sum);
  return 0;
#endif
}
