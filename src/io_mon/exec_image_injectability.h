/* Can the monitor shim enter the image an exec will run?  (Linux)
 *
 * The ONE classifier of exec targets, shared by the consumer (the root spawn
 * in fs_snoop.nim, through exec_image_injectability.nim) and the preloaded
 * shim (its exec, posix_spawn and raw-execve paths, through
 * hooks/linux_preload_runtime.nim). Each of those translation units
 * `#include`s this file, so every definition here is `static`: no symbol is
 * exported from the shim (two distinct shims can be loaded into one process)
 * and the consumer and the shim cannot bind to each other's copy.
 *
 * WHY IT EXISTS. The shim reaches a new image through LD_PRELOAD, which only
 * the dynamic loader of the SAME ELF class and machine honours. A 32-bit
 * image under the 64-bit shim runs anyway -- glibc prints "wrong ELF class:
 * ignored" -- and a static image has no loader at all; either way the image
 * runs with no shim and leaves no record. The merge's process-tree signals
 * (writer.nim, `unmonitoredSubtreeLossDetails`) cannot see that when the
 * unmonitored image later execs a monitored one IN THE SAME PID: the
 * monitored image emits that pid's process-start, and the unmonitored one
 * records no exec, so the starts/execs accounting balances. The only point
 * that knows an uninjectable image was entered is the monitored context that
 * starts it, so that context classifies the target with this file and
 * records event-loss there (spec: reprobuild-pm Monitor-Hook-Shim.md,
 * "Failure Semantics").
 *
 * WHAT IS UNINJECTABLE (deliberately conservative: a false verdict makes an
 * action uncacheable, a missed one publishes an incomplete capture):
 *   - an ELF whose EI_CLASS, EI_DATA or e_machine differs from this build's;
 *   - an ELF with no PT_INTERP that is ET_EXEC (static), or ET_DYN with no
 *     DT_SONAME (static-pie). An ET_DYN with no PT_INTERP but WITH a
 *     DT_SONAME is the dynamic loader run directly (`ld-linux*.so.2 prog`),
 *     which does honour LD_PRELOAD (measured: the shim records a
 *     process-start for it), so it is NOT flagged;
 *   - a `#!` script whose interpreter (resolved as the kernel does, through
 *     at most IOMON_EXEC_MAX_IMAGES images) is any of the above.
 * Never flagged: a file that is neither ELF nor `#!` (a shell retries
 * ENOEXEC as a script; binfmt_misc may claim it), and a target that does not
 * exist, is not a regular file or is not executable: the exec fails, and
 * Python's PATH loop, for one, tries nonexistent candidates.
 *
 * EXECUTE-ONLY IMAGES. A regular file the caller may execute but not read
 * (mode --x) is run by the kernel, yet its header cannot be inspected here.
 * It is flagged (IOMON_EXEC_UNREADABLE): an entry whose injectability cannot
 * be verified is graded as a loss rather than assumed monitored, because a
 * static or other-class execute-only image is exactly the one that would
 * otherwise publish an incomplete capture as complete. The cost is a loss for
 * a dynamic execute-only image the shim does enter -- rare in builds, and the
 * safe direction (a re-run, never a false skip). A caller with
 * CAP_DAC_OVERRIDE (root) reads the header anyway and gets the ordinary
 * verdict.
 *
 * RESIDUAL. The verdict is made before the exec; an exec that then fails
 * leaves a loss for an image that never ran. Checking X_OK and the file type
 * first removes the common failures (EACCES, ENOENT). What remains is chiefly
 * ENOEXEC for an ELF of a machine this kernel cannot run natively and no
 * binfmt_misc handler claims (an aarch64 test binary run by a cross build's
 * configure on x86_64, say), plus ETXTBSY/E2BIG/ENOMEM races. Each leaves the
 * capture incomplete (re-run, never a false skip), which is the safe
 * direction.
 *
 * SAFETY CONTRACT, because the shim calls this from inside hooks, in a vfork
 * child, and from the inline-syscall SIGTRAP handler: no allocation, no
 * locks, no libc beyond memset/memcpy/memchr/strlen, bounded stack (about
 * 1.5 KiB plus the caller's detail buffer), and every file access goes
 * through the caller's `iomon_exec_io` -- raw system calls in the shim, so
 * nothing recurses into its hooks or is recorded as an observation; plain
 * libc in the consumer. errno is the caller's to preserve.
 */
#ifndef IOMON_EXEC_IMAGE_INJECTABILITY_H
#define IOMON_EXEC_IMAGE_INJECTABILITY_H

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <string.h>

/* File access the classifier needs, supplied by the caller. Each returns
 * what the system call does: a value >= 0 on success, -errno on failure. */
typedef struct iomon_exec_io {
  long (*openat)(int dirfd, const char *path, int flags);
  long (*pread)(int fd, void *buf, unsigned long len, long offset);
  /* 1 when `fd` is a regular file, 0 when not, -errno on failure. */
  long (*is_regular)(int fd);
  /* faccessat(dirfd, path, X_OK, 0). */
  long (*access_x)(int dirfd, const char *path);
  void (*close)(int fd);
} iomon_exec_io;

enum {
  IOMON_EXEC_INJECTABLE = 0,
  IOMON_EXEC_OTHER_ELF = 1,
  IOMON_EXEC_STATIC = 2,
  IOMON_EXEC_STATIC_PIE = 3,
  IOMON_EXEC_UNREADABLE = 4
};

/* What `iomon_exec_open_image` reports instead of a readable descriptor. */
enum {
  IOMON_EXEC_OPEN_WILL_FAIL = -1,   /* the exec fails on it: never flagged */
  IOMON_EXEC_OPEN_EXEC_ONLY = -2    /* the kernel runs it; it cannot be read */
};

/* The images one exec may pass through: fs/exec.c `exec_binprm` lets
 * `search_binary_handler` run for depth 0..5 and fails with ELOOP beyond, so
 * a `#!` chain longer than this cannot run anything and is not flagged. */
#define IOMON_EXEC_MAX_IMAGES 6
/* BINPRM_BUF_SIZE (include/uapi/linux/binfmts.h): the bytes the kernel reads
 * from an image to choose its handler, and so the longest `#!` line it
 * parses. */
#define IOMON_BINPRM_BUF 256
/* How a candidate image is opened to read its header. O_NONBLOCK: the file
 * type is checked only after the open, and an executable-mode FIFO opened
 * without it would block the exec'ing thread (inside a hook) until a writer
 * appeared; it does not affect pread on a regular file. O_NOCTTY: a terminal
 * device must never become the controlling tty as a side effect. */
#define IOMON_EXEC_OPEN_FLAGS (O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY)

/* This build's ELF identity: what the loader that loads THIS code accepts. */
#define IOMON_SELF_CLASS (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define IOMON_SELF_DATA ELFDATA2MSB
#else
#define IOMON_SELF_DATA ELFDATA2LSB
#endif
#if defined(__x86_64__)
#define IOMON_SELF_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define IOMON_SELF_MACHINE EM_AARCH64
#elif defined(__i386__)
#define IOMON_SELF_MACHINE EM_386
#elif defined(__arm__)
#define IOMON_SELF_MACHINE EM_ARM
#elif defined(__riscv)
#define IOMON_SELF_MACHINE EM_RISCV
#else
/* Unknown machine: compare class and byte order only. Never a false loss. */
#define IOMON_SELF_MACHINE 0
#endif

/* NUL-terminated appends into `out[cap]`, truncating; return the new length. */
static size_t iomon_exec_append(char *out, size_t at, size_t cap,
                                const char *text) {
  if (cap == 0) return 0;
  while (text != NULL && *text != '\0' && at + 1 < cap) out[at++] = *text++;
  out[at] = '\0';
  return at;
}

static size_t iomon_exec_append_dec(char *out, size_t at, size_t cap,
                                    unsigned long value) {
  char digits[24];
  int n = 0;
  do {
    digits[n++] = (char)('0' + value % 10);
    value /= 10;
  } while (value != 0 && n < (int)sizeof(digits));
  char text[25];
  int k = 0;
  while (n > 0) text[k++] = digits[--n];
  text[k] = '\0';
  return iomon_exec_append(out, at, cap, text);
}

static int iomon_exec_spacetab(char c) { return c == ' ' || c == '\t'; }

/* The interpreter name of a `#!` line, parsed as fs/binfmt_script.c
 * `load_script` does (Linux 5.0+) over the zero-filled BINPRM buffer, into
 * `out` (IOMON_BINPRM_BUF bytes). 0 when the kernel would fail with
 * ENOEXEC: only spaces, an interpreter name truncated by the buffer end, or
 * no name. */
static int iomon_exec_script_interpreter(const unsigned char *raw,
                                          char *out) {
  const char *buf = (const char *)raw;
  const char *buf_end = buf + IOMON_BINPRM_BUF - 1;
  const char *i_end = (const char *)memchr(buf, '\n', IOMON_BINPRM_BUF);
  const char *p;
  if (i_end == NULL) {
    /* No newline: the name must end inside the buffer. */
    for (p = buf + 2; p <= buf_end && iomon_exec_spacetab(*p); p++) {}
    if (p > buf_end) return 0;
    while (p <= buf_end && !iomon_exec_spacetab(*p) && *p != '\0') p++;
    if (p > buf_end) return 0;
    i_end = buf_end;
  }
  while (i_end > buf + 2 && iomon_exec_spacetab(i_end[-1])) i_end--;
  const char *name = buf + 2;
  while (name < i_end && iomon_exec_spacetab(*name)) name++;
  if (name >= i_end) return 0;
  const char *name_end = name;
  while (name_end < i_end && !iomon_exec_spacetab(*name_end) &&
         *name_end != '\0')
    name_end++;
  size_t len = (size_t)(name_end - name);
  if (len == 0 || len >= IOMON_BINPRM_BUF) return 0;
  memcpy(out, name, len);
  out[len] = '\0';
  return 1;
}

/* The verdict for one ELF image whose first `n` bytes are `head`, and why. */
static int iomon_exec_elf_verdict(const iomon_exec_io *io, int fd,
                                  const unsigned char *head, long n,
                                  char *why, size_t why_cap) {
  if (n < EI_NIDENT + 4) return IOMON_EXEC_INJECTABLE; /* the kernel refuses */
  unsigned klass = head[EI_CLASS], data = head[EI_DATA];
  /* e_machine sits at offset 18 in both classes, in the file's byte order. */
  unsigned machine = data == ELFDATA2MSB
      ? ((unsigned)head[18] << 8) | head[19]
      : ((unsigned)head[19] << 8) | head[18];
  if (klass != (unsigned)IOMON_SELF_CLASS || data != (unsigned)IOMON_SELF_DATA ||
      (IOMON_SELF_MACHINE != 0 && machine != (unsigned)IOMON_SELF_MACHINE)) {
    size_t at = iomon_exec_append(why, 0, why_cap,
        "other ELF class or machine than the shim, whose loader refuses "
        "it (EI_CLASS=");
    at = iomon_exec_append_dec(why, at, why_cap, klass);
    at = iomon_exec_append(why, at, why_cap, " EI_DATA=");
    at = iomon_exec_append_dec(why, at, why_cap, data);
    at = iomon_exec_append(why, at, why_cap, " e_machine=");
    at = iomon_exec_append_dec(why, at, why_cap, machine);
    at = iomon_exec_append(why, at, why_cap, "; shim EI_CLASS=");
    at = iomon_exec_append_dec(why, at, why_cap, (unsigned)IOMON_SELF_CLASS);
    at = iomon_exec_append(why, at, why_cap, " e_machine=");
    at = iomon_exec_append_dec(why, at, why_cap, (unsigned)IOMON_SELF_MACHINE);
    iomon_exec_append(why, at, why_cap, ")");
    return IOMON_EXEC_OTHER_ELF;
  }
  /* Our own class and machine: is there a loader to honour LD_PRELOAD? */
  ElfW(Ehdr) eh;
  if ((size_t)n < sizeof(eh)) return IOMON_EXEC_INJECTABLE;
  memcpy(&eh, head, sizeof(eh));
  if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN)
    return IOMON_EXEC_INJECTABLE;   /* the kernel refuses to run it */
  /* fs/binfmt_elf.c `load_elf_phdrs` rejects these too. */
  if (eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0 ||
      (unsigned long)eh.e_phnum * sizeof(ElfW(Phdr)) > 65536)
    return IOMON_EXEC_INJECTABLE;
  int has_interp = 0, has_dynamic = 0;
  unsigned long dyn_off = 0, dyn_size = 0;
  ElfW(Phdr) ph[8];
  for (unsigned i = 0; i < eh.e_phnum && !has_interp;) {
    unsigned batch = eh.e_phnum - i;
    if (batch > sizeof(ph) / sizeof(ph[0])) batch = sizeof(ph) / sizeof(ph[0]);
    long want = (long)(batch * sizeof(ElfW(Phdr)));
    long got = io->pread(fd, ph, (unsigned long)want,
                          (long)(eh.e_phoff + (unsigned long)i * sizeof(ElfW(Phdr))));
    if (got != want) return IOMON_EXEC_INJECTABLE;   /* unreadable: no claim */
    for (unsigned k = 0; k < batch; k++) {
      if (ph[k].p_type == PT_INTERP) has_interp = 1;
      if (ph[k].p_type == PT_DYNAMIC) {
        has_dynamic = 1;
        dyn_off = (unsigned long)ph[k].p_offset;
        dyn_size = (unsigned long)ph[k].p_filesz;
      }
    }
    i += batch;
  }
  if (has_interp) return IOMON_EXEC_INJECTABLE;
  if (eh.e_type == ET_EXEC) {
    iomon_exec_append(why, 0, why_cap,
        "statically linked, no loader to preload into (ET_EXEC without "
        "PT_INTERP)");
    return IOMON_EXEC_STATIC;
  }
  /* ET_DYN without PT_INTERP: the loader itself (it has a DT_SONAME), or a
   * static-pie (it has none). */
  if (has_dynamic) {
    ElfW(Dyn) dyn[16];
    unsigned long done = 0;
    while (done + sizeof(ElfW(Dyn)) <= dyn_size) {
      unsigned long left = (dyn_size - done) / sizeof(ElfW(Dyn));
      unsigned long batch = left < 16 ? left : 16;
      long want = (long)(batch * sizeof(ElfW(Dyn)));
      if (io->pread(fd, dyn, (unsigned long)want, (long)(dyn_off + done)) !=
          want)
        return IOMON_EXEC_INJECTABLE;
      for (unsigned long k = 0; k < batch; k++) {
        if (dyn[k].d_tag == DT_SONAME) return IOMON_EXEC_INJECTABLE;
        if (dyn[k].d_tag == DT_NULL) {
          done = dyn_size;
          break;
        }
      }
      if (done < dyn_size) done += (unsigned long)want;
    }
  }
  iomon_exec_append(why, 0, why_cap,
      "static-pie, no loader to preload into (ET_DYN without PT_INTERP or "
      "DT_SONAME)");
  return IOMON_EXEC_STATIC_PIE;
}

/* Open the image an exec of `name` (relative to `dirfd`) would load, to read
 * its header. Returns the descriptor; IOMON_EXEC_OPEN_WILL_FAIL when the exec
 * fails on it (not executable for the caller, missing, not a regular file);
 * or IOMON_EXEC_OPEN_EXEC_ONLY when it is an executable regular file the
 * caller cannot read. That last case is told apart through an O_PATH
 * descriptor, which needs no read permission and still answers fstat. */
static long iomon_exec_open_image(const iomon_exec_io *io, int dirfd,
                                  const char *name, int nofollow) {
  int follow = nofollow ? O_NOFOLLOW : 0;
  if (io->access_x(dirfd, name) != 0) return IOMON_EXEC_OPEN_WILL_FAIL;
  long fd = io->openat(dirfd, name, IOMON_EXEC_OPEN_FLAGS | follow);
  if (fd >= 0) {
    if (io->is_regular((int)fd) == 1) return fd;
    io->close((int)fd);
    return IOMON_EXEC_OPEN_WILL_FAIL;
  }
  if (fd != -EACCES) return IOMON_EXEC_OPEN_WILL_FAIL;
  long probe = io->openat(dirfd, name, O_PATH | O_CLOEXEC | follow);
  if (probe < 0) return IOMON_EXEC_OPEN_WILL_FAIL;
  long regular = io->is_regular((int)probe);
  io->close((int)probe);
  return regular == 1 ? IOMON_EXEC_OPEN_EXEC_ONLY : IOMON_EXEC_OPEN_WILL_FAIL;
}

/* Classify what `execveat(dirfd, path, ..., at_flags)` would run. Returns an
 * IOMON_EXEC_* verdict; when it is not IOMON_EXEC_INJECTABLE, `detail` holds
 * "<why> image=<the uninjectable image>[ script=<the #! file>]". `display`,
 * when not NULL, names the exec'd file in that text instead of `path` (an
 * fexecve's descriptor is shown by its file name, not /proc/self/fd/N). */
static int iomon_exec_image_classify(const iomon_exec_io *io, int dirfd,
                                      const char *path, int at_flags,
                                      const char *display, char *detail,
                                      size_t detail_cap) {
  char fd_path[32];
  if (detail_cap > 0) detail[0] = '\0';
  if (path == NULL) return IOMON_EXEC_INJECTABLE;
  if (path[0] == '\0') {
    if (!(at_flags & AT_EMPTY_PATH) || dirfd < 0) return IOMON_EXEC_INJECTABLE;
    /* AT_EMPTY_PATH: the descriptor itself, reopened through procfs. */
    size_t at = iomon_exec_append(fd_path, 0, sizeof(fd_path),
                                  "/proc/self/fd/");
    iomon_exec_append_dec(fd_path, at, sizeof(fd_path), (unsigned long)dirfd);
    dirfd = AT_FDCWD;
    path = fd_path;
    at_flags = 0;
  }
  const char *top = display != NULL ? display : path;
  char names[2][IOMON_BINPRM_BUF];
  const char *name = path;
  int nofollow = (at_flags & AT_SYMLINK_NOFOLLOW) != 0;
  int via_script = 0;
  for (int depth = 0; depth < IOMON_EXEC_MAX_IMAGES; depth++) {
    long fd = iomon_exec_open_image(io, dirfd, name, nofollow);
    /* What the exec would fail on is never flagged. */
    if (fd == IOMON_EXEC_OPEN_WILL_FAIL) return IOMON_EXEC_INJECTABLE;
    if (fd == IOMON_EXEC_OPEN_EXEC_ONLY) {
      /* See EXECUTE-ONLY IMAGES above. */
      size_t at = iomon_exec_append(detail, 0, detail_cap,
          "execute-only image: header unreadable, injection unverifiable "
          "image=");
      at = iomon_exec_append(detail, at, detail_cap, via_script ? name : top);
      if (via_script) {
        at = iomon_exec_append(detail, at, detail_cap, " script=");
        iomon_exec_append(detail, at, detail_cap, top);
      }
      return IOMON_EXEC_UNREADABLE;
    }
    unsigned char head[IOMON_BINPRM_BUF];
    memset(head, 0, sizeof(head));
    long n = io->pread((int)fd, head, sizeof(head), 0);
    if (n >= 2 && head[0] == '#' && head[1] == '!') {
      io->close((int)fd);
      char *next = names[depth & 1];
      if (!iomon_exec_script_interpreter(head, next))
        return IOMON_EXEC_INJECTABLE;
      /* The kernel opens the interpreter relative to the working directory,
       * following symlinks, whatever the script was reached through. */
      name = next;
      dirfd = AT_FDCWD;
      nofollow = 0;
      via_script = 1;
      continue;
    }
    if (n < 4 || memcmp(head, ELFMAG, SELFMAG) != 0) {
      io->close((int)fd);
      return IOMON_EXEC_INJECTABLE;
    }
    char why[160];
    why[0] = '\0';
    int verdict = iomon_exec_elf_verdict(io, (int)fd, head, n, why,
                                          sizeof(why));
    io->close((int)fd);
    if (verdict != IOMON_EXEC_INJECTABLE) {
      size_t at = iomon_exec_append(detail, 0, detail_cap, why);
      at = iomon_exec_append(detail, at, detail_cap, " image=");
      at = iomon_exec_append(detail, at, detail_cap, via_script ? name : top);
      if (via_script) {
        at = iomon_exec_append(detail, at, detail_cap, " script=");
        iomon_exec_append(detail, at, detail_cap, top);
      }
    }
    return verdict;
  }
  return IOMON_EXEC_INJECTABLE;
}

/* The file a PATH-searching exec of `file` runs: glibc's execvpe and
 * posix_spawnp search `search` (the CALLER's PATH; glibc's default when it
 * is unset is "/bin:/usr/bin"), an empty element meaning the working
 * directory, and run the first candidate the kernel accepts -- so the first
 * that is executable and a regular file (execve's EACCES on anything else
 * makes them try the next), readable or not. A `file` containing a slash is
 * not searched. A relative candidate (from a relative PATH element, or the
 * empty one) is looked up relative to `dirfd`, the directory the exec runs
 * in. Returns 1 with the path in `out`, 0 when no candidate would run. */
static int iomon_exec_search_path(const iomon_exec_io *io, int dirfd,
                                  const char *file, const char *search,
                                  char *out, size_t out_cap) {
  if (file == NULL || file[0] == '\0' || out_cap == 0) return 0;
  if (strchr(file, '/') != NULL) {
    size_t at = iomon_exec_append(out, 0, out_cap, file);
    return at == strlen(file);
  }
  if (search == NULL) search = "/bin:/usr/bin";
  size_t file_len = strlen(file);
  const char *p = search;
  for (;;) {
    const char *end = strchr(p, ':');
    size_t dir_len = end != NULL ? (size_t)(end - p) : strlen(p);
    /* dir + "/" + file + NUL must fit; a longer candidate is skipped, as
     * glibc skips one longer than PATH_MAX. */
    if (dir_len + 1 + file_len + 1 <= out_cap) {
      size_t at = 0;
      if (dir_len > 0) {
        memcpy(out, p, dir_len);
        at = dir_len;
        out[at++] = '/';
      }
      memcpy(out + at, file, file_len + 1);
      /* An execute-only candidate runs too: the search must stop at it. */
      long fd = iomon_exec_open_image(io, dirfd, out, 0);
      if (fd == IOMON_EXEC_OPEN_EXEC_ONLY) return 1;
      if (fd >= 0) {
        io->close((int)fd);
        return 1;
      }
    }
    if (end == NULL) break;
    p = end + 1;
  }
  out[0] = '\0';
  return 0;
}

#endif /* IOMON_EXEC_IMAGE_INJECTABILITY_H */
