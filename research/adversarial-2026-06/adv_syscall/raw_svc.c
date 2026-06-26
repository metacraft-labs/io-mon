// EVASION A: inline arm64 `svc #0x80` raw syscalls. These go straight to the
// kernel and NEVER execute the libsystem open/read wrapper bodies, so neither
// the __DATA,__interpose rebinding (no import stub used) NOR the mach_vm_remap
// body-patch (wrapper entry never entered) can observe them.
//
// macOS arm64 BSD syscall ABI: syscall number in x16, args x0..x5, `svc #0x80`.
// On error the carry flag is set and x0 holds errno; we ignore that detail and
// just check the return value. BSD numbers: open=5, read=3, close=6, write=4.
#include <stdint.h>
#include <string.h>

static int64_t sc3(int64_t nr, int64_t a0, int64_t a1, int64_t a2) {
  register int64_t x0 asm("x0") = a0;
  register int64_t x1 asm("x1") = a1;
  register int64_t x2 asm("x2") = a2;
  register int64_t x16 asm("x16") = nr;
  asm volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "cc", "memory");
  return x0;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  const char *path = argv[1];
  // open(path, O_RDONLY=0, 0)
  int64_t fd = sc3(5, (int64_t)path, 0, 0);
  if (fd < 0) return 1;
  char buf[256];
  int64_t n = sc3(3, fd, (int64_t)buf, sizeof buf); // read
  if (n > 0) sc3(4, 1, (int64_t)buf, n);            // write to stdout(1)
  sc3(6, fd, 0, 0);                                  // close
  return 0;
}
