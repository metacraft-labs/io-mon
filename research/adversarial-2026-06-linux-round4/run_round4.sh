#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROUND="$ROOT/research/adversarial-2026-06-linux-round4"
RUN_DIR="${RUN_DIR:-/tmp/io_mon_linux_round4}"
CC="${CC:-cc}"
IO_MON="${IO_MON:-$ROOT/build/bin/io-mon}"

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/probes" "$RUN_DIR/out"

cd "$ROOT"
bash scripts/build_shim.sh >/dev/null

cat >"$RUN_DIR/probes/content_channels.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <unistd.h>

static ssize_t xsplice(int in, int out) {
  int p[2];
  if (pipe(p) != 0) return -1;
  ssize_t n = splice(in, NULL, p[1], NULL, 4096, 0);
  if (n > 0) {
    ssize_t m = splice(p[0], NULL, out, NULL, (size_t)n, 0);
    if (m < 0) n = -1;
  }
  close(p[0]);
  close(p[1]);
  return n;
}

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int in = open(argv[2], O_RDONLY);
  if (in < 0) return 3;
  int out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) return 4;
  char a[32] = {0};
  char b[32] = {0};
  ssize_t n = -1;
  if (strcmp(argv[1], "read") == 0) {
    n = read(in, a, sizeof(a));
    if (n > 0 && write(out, a, (size_t)n) != n) return 5;
  } else if (strcmp(argv[1], "pread") == 0) {
    n = pread(in, a, sizeof(a), 0);
    if (n > 0 && write(out, a, (size_t)n) != n) return 6;
  } else if (strcmp(argv[1], "readv") == 0) {
    struct iovec iov[2] = {{a, 16}, {b, 16}};
    n = readv(in, iov, 2);
    if (n > 0 && write(out, a, 16) < 0) return 7;
  } else if (strcmp(argv[1], "preadv") == 0) {
    struct iovec iov[2] = {{a, 16}, {b, 16}};
    n = preadv(in, iov, 2, 0);
    if (n > 0 && write(out, a, 16) < 0) return 8;
  } else if (strcmp(argv[1], "sendfile") == 0) {
    n = sendfile(out, in, NULL, 4096);
  } else if (strcmp(argv[1], "copy_file_range") == 0) {
    n = copy_file_range(in, NULL, out, NULL, 4096, 0);
  } else if (strcmp(argv[1], "splice") == 0) {
    n = xsplice(in, out);
  } else {
    return 9;
  }
  close(out);
  close(in);
  if (n < 0) {
    fprintf(stderr, "%s failed: %s\n", argv[1], strerror(errno));
    return 10;
  }
  return n > 0 ? 0 : 11;
}
C

cat >"$RUN_DIR/probes/raw_sendfile.c" <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int in = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY, 0);
  if (in < 0) return 2;
  int out = (int)syscall(SYS_openat, AT_FDCWD, argv[2],
                         O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) return 3;
  long n = syscall(SYS_sendfile, out, in, 0, 4096);
  syscall(SYS_close, out);
  syscall(SYS_close, in);
  return n > 0 ? 0 : 4;
}
C

cat >"$RUN_DIR/probes/hardlink_alias.c" <<'C'
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  unlink(argv[2]);
  if (link(argv[1], argv[2]) != 0) return 2;
  int fd = open(argv[2], O_RDONLY);
  if (fd < 0) return 3;
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  return n > 0 ? 0 : 4;
}
C

cat >"$RUN_DIR/probes/rename_staging.c" <<'C'
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) return 2;
  if (write(fd, "renamed\n", 8) != 8) return 3;
  close(fd);
  return rename(argv[1], argv[2]) == 0 ? 0 : 4;
}
C

cat >"$RUN_DIR/probes/nonfile.c" <<'C'
#define _GNU_SOURCE
#include <sys/random.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
int main(void) {
  char buf[16];
  struct utsname u;
  struct timespec ts;
  volatile const char *v = getenv("IO_MON_ROUND4_ENV");
  (void)v;
  uname(&u);
  sysconf(_SC_NPROCESSORS_ONLN);
  clock_gettime(CLOCK_REALTIME, &ts);
  getrandom(buf, sizeof(buf), 0);
  return 0;
}
C

"$CC" "$RUN_DIR/probes/content_channels.c" -o "$RUN_DIR/content_channels"
"$CC" "$RUN_DIR/probes/raw_sendfile.c" -o "$RUN_DIR/raw_sendfile"
"$CC" "$RUN_DIR/probes/hardlink_alias.c" -o "$RUN_DIR/hardlink_alias"
"$CC" "$RUN_DIR/probes/rename_staging.c" -o "$RUN_DIR/rename_staging"
"$CC" "$RUN_DIR/probes/nonfile.c" -o "$RUN_DIR/nonfile"

src="$RUN_DIR/source.txt"
printf 'round4 source marker for adversarial content probes\n' >"$src"

printf 'probe\texit\tcompleteness\tfile_read_source\tfile_write_output\tevent_loss\tclassification\n' >"$RUN_DIR/summary.tsv"

run_probe() {
  local name="$1"
  shift
  local dep="$RUN_DIR/out/$name.rdep"
  local inspect="$RUN_DIR/out/$name.inspect.txt"
  local out="$RUN_DIR/out/$name.out"
  set +e
  "$IO_MON" run --depfile "$dep" -- "$@" >"$RUN_DIR/out/$name.stdout" 2>"$RUN_DIR/out/$name.stderr"
  local code=$?
  set -e
  "$IO_MON" inspect "$dep" >"$inspect"
  local completeness file_read file_write event_loss classification
  completeness="$(sed -n '1s/.*completeness=//p' "$inspect" | awk '{print $1}')"
  awk -v src="$src" '/^#[0-9]+ .*file-read/ && index($0, src) { found=1 } END { exit(found ? 0 : 1) }' "$inspect" && file_read=yes || file_read=no
  awk -v out="$out" '/^#[0-9]+ .*file-write/ && index($0, out) { found=1 } END { exit(found ? 0 : 1) }' "$inspect" && file_write=yes || file_write=no
  grep -Eq '^#[0-9]+ event-loss' "$inspect" && event_loss=yes || event_loss=no
  classification="captured"
  if [ "$completeness" = "mcIncomplete" ]; then
    classification="fail-closed/incomplete"
  elif [ "$file_read" = "no" ] || [ "$event_loss" = "yes" ]; then
    classification="unsupported-capability-gated"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$code" "$completeness" "$file_read" "$file_write" "$event_loss" \
    "$classification" >>"$RUN_DIR/summary.tsv"
}

run_probe baseline_read "$RUN_DIR/content_channels" read "$src" "$RUN_DIR/out/baseline_read.out"
run_probe pread "$RUN_DIR/content_channels" pread "$src" "$RUN_DIR/out/pread.out"
run_probe readv "$RUN_DIR/content_channels" readv "$src" "$RUN_DIR/out/readv.out"
run_probe preadv "$RUN_DIR/content_channels" preadv "$src" "$RUN_DIR/out/preadv.out"
run_probe sendfile "$RUN_DIR/content_channels" sendfile "$src" "$RUN_DIR/out/sendfile.out"
run_probe copy_file_range "$RUN_DIR/content_channels" copy_file_range "$src" "$RUN_DIR/out/copy_file_range.out"
run_probe splice "$RUN_DIR/content_channels" splice "$src" "$RUN_DIR/out/splice.out"
run_probe raw_sendfile "$RUN_DIR/raw_sendfile" "$src" "$RUN_DIR/out/raw_sendfile.out"
run_probe hardlink_alias "$RUN_DIR/hardlink_alias" "$src" "$RUN_DIR/out/hardlink_alias.link"
run_probe rename_staging "$RUN_DIR/rename_staging" "$RUN_DIR/out/rename_staging.tmp" "$RUN_DIR/out/rename_staging.final"
IO_MON_ROUND4_ENV=secret run_probe nonfile "$RUN_DIR/nonfile"

cp "$RUN_DIR/summary.tsv" "$ROUND/summary.tsv"
printf 'wrote %s and per-probe artifacts under %s\n' "$ROUND/summary.tsv" "$RUN_DIR"
