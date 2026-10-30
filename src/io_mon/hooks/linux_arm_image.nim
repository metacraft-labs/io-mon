## 32-bit ARM: may an ELF image hold Thumb-state code?
##
## The inline syscall-site scanner on ARM recognises word-aligned ARM-state
## `svc #0` only (`stackable_hooks/platform/linux_raw_syscalls`); a Thumb `svc`
## is a 16-bit halfword it cannot discover soundly. The shim therefore judges
## every non-system executable mapping it scans with `armImageThumbVerdict`
## and records a Thumb-capable image as a coverage loss, so the capture grades
## `mcIncomplete` instead of silently missing the call. The judgement is a
## module of its own so the shim and the tests share one implementation.
##
## On other architectures the verdict is `atvNotApplicable`.

type
  ArmThumbVerdict* = enum
    atvArmOnly = 0        ## the image cannot contain Thumb code
    atvThumbPossible = 1  ## it may (or does): a coverage loss when scanned
    atvUnknown = 2        ## unreadable, not ELF32/ARM, or no `.ARM.attributes`
    atvNotApplicable = 3  ## not a 32-bit ARM build

when defined(linux) and defined(arm):
  {.emit: """
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
""" & """/* 32-bit ARM: may the ELF image at `path` hold Thumb-state code?
 *
 * The inline syscall-site scanner on ARM recognises word-aligned ARM-state
 * `svc #0` only; a Thumb `svc` is a 16-bit halfword it cannot discover
 * soundly. A monitored program that issues one through Thumb code would
 * therefore be UNOBSERVED while the capture graded complete -- the one place
 * the ARM port was weaker than fail-closed. So every non-system executable
 * mapping the scanner takes is judged first, and an image that may hold Thumb
 * code is recorded as a coverage loss instead.
 *
 * The judgement reads the image's `.ARM.attributes` (ARM IHI 0045, "Addenda to
 * the ABI for the ARM Architecture", section 3): Tag_CPU_arch (6),
 * Tag_THUMB_ISA_use (9) and Tag_ABI_VFP_args (28) of the file-scope
 * subsection of the "aeabi" vendor section. Measured on Raspberry Pi OS 13
 * armhf (2026-10-30): its userland is built for ARMv6 with the hard-float
 * ABI -- `Tag_CPU_arch: v6; Tag_THUMB_ISA_use: Thumb-1; Tag_ABI_VFP_args: VFP
 * registers` on /usr/bin/gcc, /bin/sh, /usr/bin/make, /usr/bin/ld and libc.
 * GCC refuses to emit Thumb-1 code for the hard-float ABI ("sorry,
 * unimplemented: Thumb-1 'hard-float' VFP ABI"), so such an image contains no
 * Thumb functions and is judged ARM-only. An image built for ARMv7 or later
 * with Thumb permitted (`-march=armv7-a -mthumb`: v7 / Thumb-2) may, and is
 * judged Thumb-capable -- as is an ARMv7 image built with -marm, whose
 * attributes read the same; that false positive is the conservative side.
 * An image with an odd-valued STT_FUNC symbol (a Thumb function) is Thumb-
 * capable whatever its attributes say. An image without the section cannot
 * be judged and is Thumb-capable (fail closed); the one such image seen,
 * GCC's cc1, lives under /usr/lib and is never scanned anyway.
 *
 * Returns 0 = ARM-only, 1 = may hold Thumb code, 2 = unreadable/unknown.
 * `reason[cap]` names why. */
static unsigned long ct_arm_read_uleb(const unsigned char **p, const unsigned char *end) {
  unsigned long v = 0; unsigned shift = 0;
  while (*p < end) {
    unsigned char b = *(*p)++;
    v |= (unsigned long)(b & 0x7f) << shift; shift += 7;
    if (!(b & 0x80) || shift > 28) break;
  }
  return v;
}
static int ct_arm_tag_is_string(unsigned long tag) {
  /* Tag_CPU_raw_name, Tag_CPU_name, Tag_compatibility (uleb + string), and the
   * two string-valued tags 65 (also_compatible_with) and 67 (conformance). */
  return tag == 4 || tag == 5 || tag == 32 || tag == 65 || tag == 67;
}
static int ct_arm_image_thumb_verdict(const char *path, char *reason, size_t cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { snprintf(reason, cap, "open failed"); return 2; }
  Elf32_Ehdr eh; int rc = 2;
  long have_arch = -1, have_thumb = -1, have_vfp = -1;
  int odd_func = 0, attrs_seen = 0;
  if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS32 || eh.e_machine != EM_ARM || eh.e_shentsize != sizeof(Elf32_Shdr) ||
      eh.e_shnum == 0 || eh.e_shnum > 4096) {
    snprintf(reason, cap, "not a readable ELF32 ARM image"); close(fd); return 2;
  }
  for (unsigned i = 0; i < eh.e_shnum; i++) {
    Elf32_Shdr sh;
    if (pread(fd, &sh, sizeof sh, eh.e_shoff + (off_t)i * sizeof sh) != (ssize_t)sizeof sh) break;
    if (sh.sh_type == 0x70000003u /* SHT_ARM_ATTRIBUTES */ && sh.sh_size > 1 && sh.sh_size < 65536) {
      unsigned char *buf = (unsigned char *)malloc(sh.sh_size);
      if (buf == NULL) break;
      if (pread(fd, buf, sh.sh_size, sh.sh_offset) == (ssize_t)sh.sh_size && buf[0] == 'A') {
        const unsigned char *p = buf + 1, *end = buf + sh.sh_size;
        while (p + 4 <= end) {                       /* vendor sections */
          uint32_t vlen; memcpy(&vlen, p, 4);
          const unsigned char *vend = (vlen >= 4 && p + vlen <= end) ? p + vlen : end;
          const unsigned char *q = p + 4;
          size_t nlen = strnlen((const char *)q, (size_t)(vend - q));
          int aeabi = (nlen == 5 && memcmp(q, "aeabi", 5) == 0);
          q += nlen + 1;
          while (aeabi && q + 5 <= vend) {           /* sub-subsections */
            unsigned char kind = *q; uint32_t slen; memcpy(&slen, q + 1, 4);
            const unsigned char *send = (slen >= 5 && q + slen <= vend) ? q + slen : vend;
            const unsigned char *r = q + 5;
            if (kind == 1) {                         /* Tag_File */
              attrs_seen = 1;
              while (r < send) {
                unsigned long tag = ct_arm_read_uleb(&r, send);
                if (tag == 32) (void)ct_arm_read_uleb(&r, send);
                if (ct_arm_tag_is_string(tag)) { r += strnlen((const char *)r, (size_t)(send - r)) + 1; continue; }
                unsigned long val = ct_arm_read_uleb(&r, send);
                if (tag == 6) have_arch = (long)val;
                else if (tag == 9) have_thumb = (long)val;
                else if (tag == 28) have_vfp = (long)val;
              }
            }
            q = send;
          }
          p = vend;
        }
      }
      free(buf);
    } else if ((sh.sh_type == SHT_SYMTAB || sh.sh_type == SHT_DYNSYM) && sh.sh_entsize == sizeof(Elf32_Sym) &&
               sh.sh_size <= 16u * 1024u * 1024u) {
      unsigned long n = sh.sh_size / sizeof(Elf32_Sym);
      for (unsigned long k = 0; k < n && !odd_func; k += 256) {
        Elf32_Sym syms[256]; unsigned long m = n - k < 256 ? n - k : 256;
        if (pread(fd, syms, m * sizeof(Elf32_Sym), sh.sh_offset + (off_t)k * sizeof(Elf32_Sym)) != (ssize_t)(m * sizeof(Elf32_Sym))) break;
        for (unsigned long j = 0; j < m; j++)
          if (ELF32_ST_TYPE(syms[j].st_info) == STT_FUNC && syms[j].st_value != 0 && (syms[j].st_value & 1u)) { odd_func = 1; break; }
      }
    }
  }
  close(fd);
  if (odd_func) { snprintf(reason, cap, "a function symbol has an odd (Thumb) address"); return 1; }
  if (!attrs_seen) { snprintf(reason, cap, "no .ARM.attributes section"); return 2; }
  if (have_thumb == 0) { snprintf(reason, cap, "Tag_THUMB_ISA_use=No"); return 0; }
  /* Tag_CPU_arch values with no Thumb-2 and no M-profile: Pre-v4(0) .. v6(6),
   * v6KZ(7), v6K(9). v6T2 (8) has Thumb-2; 10+ is v7 or later, or M-profile. */
  int pre_v7 = have_arch >= 0 && have_arch <= 9 && have_arch != 8;
  if (pre_v7 && have_vfp == 1 && (have_thumb == 1 || have_thumb < 0)) {
    snprintf(reason, cap, "Tag_CPU_arch=%ld (pre-v7), Thumb-1 only, hard-float ABI: no Thumb code possible", have_arch);
    return 0;
  }
  snprintf(reason, cap, "Tag_CPU_arch=%ld Tag_THUMB_ISA_use=%ld Tag_ABI_VFP_args=%ld", have_arch, have_thumb, have_vfp);
  rc = 1;
  return rc;
}
int ct_linux_arm_image_thumb_verdict(char *path, char *reason, unsigned long cap) {
  return ct_arm_image_thumb_verdict(path, reason, (size_t)cap);
}

""".}
  proc cArmImageThumbVerdict(path: cstring; reason: cstring; cap: culong): cint
    {.importc: "ct_linux_arm_image_thumb_verdict", raises: [].}

proc armImageThumbVerdict*(path: string): tuple[verdict: ArmThumbVerdict, reason: string]
    {.raises: [].} =
  ## Judge the ELF image at `path`. See the C body for the rules and the
  ## measurements behind them.
  when defined(linux) and defined(arm):
    var reason: array[160, char]
    let v = cArmImageThumbVerdict(cstring(path), cast[cstring](addr reason[0]),
      culong(reason.len))
    let verdict = case v
      of 0: atvArmOnly
      of 1: atvThumbPossible
      else: atvUnknown
    (verdict, $cast[cstring](addr reason[0]))
  else:
    discard path
    (atvNotApplicable, "")
