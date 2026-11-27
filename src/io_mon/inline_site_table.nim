## Inline raw-syscall site tables: the result of the shim's code scan,
## computed once per image by a process that is not monitored, and handed to
## every monitored process that maps the same image bytes.
##
## WHY. On Linux x86-64 the shim finds the raw `syscall` instructions of every
## image it monitors by linearly decoding the image's executable sections at
## start-up (`patchInlineSyscallMapping` in `hooks/linux_preload_runtime.nim`).
## That decode is a pure function of the code bytes and of the section ranges,
## and a build runs the same compiler image hundreds of times: a GCC `cc1`
## carries about 25 MB of code, so each compile spent about 0.13 s decoding
## exactly what the previous compile had decoded.
##
## WHAT A TABLE IS. For one image file: the identity of the file the producer
## read (device, inode, size, modification and change times), and for every
## executable `PT_LOAD` of the image the code ranges the scanner would decode
## (link-time addresses of the `SHF_EXECINSTR` sections, merged exactly as
## `linux_image_code_ranges` merges them) and the link-time address of every
## site the scanner reports in them. The producer runs the very scanner the
## shim runs (`visitLinuxX8664SyscallMemory`) over the file's bytes, so the
## table is what a fresh scan of an unmodified mapping of that file reports.
##
## WHO MAY PRODUCE ONE. Only a process that is not monitored: the build engine
## or the monitor host. A monitored process never writes a table anybody else
## trusts. Tables reach the monitored tree as ONE sealed memfd
## (`createSealedSiteTableFile`): after `F_SEAL_WRITE | F_SEAL_SHRINK |
## F_SEAL_GROW | F_SEAL_SEAL` no process can change its bytes, and nothing is
## ever stored on disk, so there is no file a monitored process could replace
## for a later build. The host verifies the seals before it hands the memfd to
## the tree (`REPRO_MONITOR_SITE_TABLES` names it as `/proc/<host>/fd/<n>`).
## A monitored process can, as with every other inherited setting, give its
## own descendants a different file; the shim then reports the identity of the
## table it used (`SiteTableServedDetail`), the host accepts only the one it
## issued, and any other table leaves an event loss in the capture.
##
## WHEN THE SHIM USES ONE. Only when every one of these holds for a mapping,
## otherwise the mapping is scanned exactly as before:
##   - the table's scanner stamp equals the shim's (`siteTableScannerStamp`:
##     a digest of the decoder, scanner and code-range sources both sides were
##     compiled from);
##   - the file the shim opened for the mapping (the one whose section table
##     gives the code ranges) has the table's device, inode, size, mtime and
##     ctime, and its inode is the mapping's;
##   - that file is the mapped one: its device agrees with `/proc/self/maps`,
##     or, where maps prints another device than `stat` reports for every
##     file (btrfs prints the superblock's and `stat` reports the
##     subvolume's; an overlayfs reports its layer's), the code bytes of the
##     ranges in memory equal the file's bytes at the same offsets, read with
##     the file's identity unchanged across the read;
##   - the producer saw the file settled (its ctime at least
##     `defaultSettleNs` in the past) and unchanged across its read, so a write
##     within one timestamp tick cannot leave the identity equal;
##   - the code ranges the shim computed for the mapping equal the table's
##     ranges for that segment moved by the mapping's load bias (so the decode
##     starts at the same bytes);
##   - every page of those ranges is, per `/proc/self/pagemap`, either not yet
##     faulted in or a page-cache page of the file: no page has been written
##     (by text relocations, by self-modifying code or by an earlier patch),
##     so memory holds the file's bytes.
## Under those conditions the memory the scanner would decode is byte for byte
## the file region the producer decoded, from the same starting offsets, with
## the same decoder, so the site set is identical.
##
## Linux x86-64 only, because the inline scan is: the encoder and the format
## constants are portable, but the producer (`computeSiteTable`,
## `createSealedSiteTableFile`), the host's check (`sealedSiteTableIdentity`)
## and the shim's reader (`SiteTableView`, `openSiteTableView`,
## `serveSitesFromTable`) are declared only under
## `when defined(linux) and defined(amd64)`, and every caller must sit under
## the same condition. On other targets `io-mon run` names no table to the
## tree and the shim ignores `REPRO_MONITOR_SITE_TABLES`.

import std/[posix, strutils]
import io_mon/types
export types.SiteTableServedDetail
when defined(linux):
  import std/macros
  import stackable_hooks/platform/linux_raw_syscalls
  import stackable_hooks/platform/linux_image_code_ranges

const
  SiteTableEnv* = "REPRO_MONITOR_SITE_TABLES"
    ## The variable the host sets in the monitored tree's environment to the
    ## `/proc/<host pid>/fd/<n>` path of the sealed table memfd.
  SiteTableMagic = "IOMSITE1"
  SiteTableVersion = 1'u32
  siteTableHeaderLen = 32
  imageHeaderLen = 64
  segmentHeaderLen = 32
  defaultSettleNs* = 2_000_000_000'i64
    ## A file whose ctime is less than this far in the past gets no table.
    ## File timestamps come from a coarse clock (a jiffy on Linux, up to a
    ## second or two on some filesystems), so a write landing in the same tick
    ## as the previous change would leave mtime and ctime equal. A file last
    ## changed more than two seconds ago gets a strictly later ctime from any
    ## write after the producer's read.

when defined(linux):
  proc fnv1a64(h: var uint64; data: string) {.compileTime.} =
    for c in data:
      h = h xor uint64(ord(c))
      h = h * 0x100000001b3'u64

  macro definingFile(s: typed): untyped =
    ## The source file that defines the routine `s`, as the compiler read it.
    var n = s
    if n.kind in {nnkClosedSymChoice, nnkOpenSymChoice}:
      n = n[0]
    newLit(n.getImpl.lineInfoObj.filename)

  func hostParentDir(path: string): string =
    ## The directory part of `path`, a file name the compiler reported in the
    ## HOST's spelling (`lineInfoObj.filename`). `os.parentDir` cannot be used
    ## here: at compile time it follows the TARGET's separators, so a Windows
    ## host cross-checking `--os:linux` splits `C:\...\file.nim` on `/` only
    ## and the path collapses to "". Both separators are accepted instead; on
    ## a POSIX host a `\` cannot occur in these repository paths, so the
    ## result there is the same as `parentDir`'s.
    var i = path.high
    while i >= 0 and path[i] notin {'/', '\\'}:
      dec i
    doAssert i > 0, "no directory part in compiler-reported path: " & path
    path[0 ..< i]

  const siteTableScannerStamp* = block:
    ## Digest of every source that decides which sites a scan reports: the
    ## instruction-length decoder, the scanner, the code-range geometry and
    ## this module. A producer and a shim built from different sources get
    ## different stamps, and the shim then ignores the table.
    const scanner = definingFile(visitLinuxX8664SyscallMemory)
    const geometry = definingFile(linuxImageCodeRangesFromReader)
    var h = 0xcbf29ce484222325'u64
    fnv1a64(h, staticRead(scanner))
    fnv1a64(h, staticRead(scanner.hostParentDir().hostParentDir() &
      "/inline_hook/windows/length_decoder.c"))
    fnv1a64(h, staticRead(geometry))
    fnv1a64(h, staticRead(currentSourcePath()))
    h
else:
  const siteTableScannerStamp* = 0'u64

type
  SiteTableSegment* = object
    ## One executable `PT_LOAD` of an image.
    pOffset*, pVaddr*, pFilesz*: uint64
    ranges*: seq[tuple[start, stop: uint64]]
      ## Link-time code ranges, sorted and merged.
    sites*: seq[uint64]
      ## Link-time address of each reported site, in scan order.

  SiteTableImage* = object
    dev*, ino*, size*: uint64
    mtimeSec*, mtimeNsec*, ctimeSec*, ctimeNsec*: int64
    segments*: seq[SiteTableSegment]

  SiteTableComputation* = object
    ok*: bool
    reason*: string
      ## Why no table was produced, when `ok` is false.
    image*: SiteTableImage

proc putU32(s: var string; v: uint32) =
  for i in 0 ..< 4: s.add char((v shr (8 * i)) and 0xff)

proc putU64(s: var string; v: uint64) =
  for i in 0 ..< 8: s.add char((v shr (8 * i)) and 0xff)

proc encodeSiteTables*(images: openArray[SiteTableImage]): string =
  ## The table file's bytes: a header, then each image. Little-endian, every
  ## record length implied by counts the reader bounds-checks.
  result = SiteTableMagic
  result.putU32 SiteTableVersion
  result.putU32 uint32(images.len)
  result.putU64 siteTableScannerStamp
  result.putU64 0  # reserved
  for image in images:
    result.putU64 image.dev
    result.putU64 image.ino
    result.putU64 image.size
    result.putU64 cast[uint64](image.mtimeSec)
    result.putU64 cast[uint64](image.mtimeNsec)
    result.putU64 cast[uint64](image.ctimeSec)
    result.putU64 cast[uint64](image.ctimeNsec)
    result.putU32 uint32(image.segments.len)
    result.putU32 0
    for segment in image.segments:
      result.putU64 segment.pOffset
      result.putU64 segment.pVaddr
      result.putU64 segment.pFilesz
      result.putU32 uint32(segment.ranges.len)
      result.putU32 uint32(segment.sites.len)
      for r in segment.ranges:
        result.putU64 r.start
        result.putU64 r.stop
      for site in segment.sites:
        result.putU64 site

when defined(linux) and defined(amd64):
  const
    MFD_CLOEXEC = 1'u32
    MFD_ALLOW_SEALING = 2'u32
    F_ADD_SEALS = 1033.cint
    F_GET_SEALS = 1034.cint
    F_SEAL_SEAL = 1.cint
    F_SEAL_SHRINK = 2.cint
    F_SEAL_GROW = 4.cint
    F_SEAL_WRITE = 8.cint
    requiredSeals = F_SEAL_SEAL or F_SEAL_SHRINK or F_SEAL_GROW or F_SEAL_WRITE
    ptLoad = 1'u32
    pfX = 1'u32
    etExec = 2'u16
    etDyn = 3'u16
    # x86-64 system call numbers, for the shim side, which must not enter its
    # own libc hooks (and so must not be recorded as the process's evidence).
    sysPread64 = 17
    sysClose = 3
    sysFstat = 5
    sysMmap = 9
    sysFcntl = 72
    sysOpenat = 257
    atFdcwd = -100

  proc memfdCreate(name: cstring; flags: cuint): cint
    {.importc: "memfd_create", header: "<sys/mman.h>".}
  proc fcntlInt(fd: cint; cmd: cint; arg: cint): cint
    {.importc: "fcntl", header: "<fcntl.h>", varargs.}

  proc readU16(b: openArray[byte]; at: int): uint16 {.inline.} =
    uint16(b[at]) or (uint16(b[at + 1]) shl 8)

  proc readU32(b: openArray[byte]; at: int): uint32 {.inline.} =
    var v = 0'u32
    for i in 0 ..< 4: v = v or (uint32(b[at + i]) shl (8 * i))
    v

  proc readU64(b: openArray[byte]; at: int): uint64 {.inline.} =
    var v = 0'u64
    for i in 0 ..< 8: v = v or (uint64(b[at + i]) shl (8 * i))
    v

  proc preadFully(fd: cint; dest: pointer; len: int; offset: uint64): bool =
    var done = 0
    while done < len:
      let n = pread(fd, cast[pointer](cast[uint](dest) + uint(done)),
                    len - done, Off(offset + uint64(done)))
      if n <= 0:
        return false
      done += int(n)
    true

  proc sameIdentity(a, b: Stat): bool =
    a.st_dev == b.st_dev and a.st_ino == b.st_ino and a.st_size == b.st_size and
      a.st_mtim.tv_sec == b.st_mtim.tv_sec and
      a.st_mtim.tv_nsec == b.st_mtim.tv_nsec and
      a.st_ctim.tv_sec == b.st_ctim.tv_sec and
      a.st_ctim.tv_nsec == b.st_ctim.tv_nsec

  proc computeSiteTable*(path: string; settleNs = defaultSettleNs):
      SiteTableComputation =
    ## Scan the image at `path` the way the shim scans a mapping of it, and
    ## return its table. For a process that is NOT monitored (the engine, the
    ## monitor host, a test driver): the result is trusted by every process
    ## that maps the file. Refuses (ok = false, with the reason) a file that is
    ## not a regular ELF64 executable or shared object, one changed less than
    ## `settleNs` ago, and one that changed while it was read.
    let fd = posix.open(cstring(path), O_RDONLY or O_CLOEXEC)
    if fd < 0:
      return SiteTableComputation(reason: "open failed: " & $strerror(errno))
    defer: discard posix.close(fd)
    var before: Stat
    if fstat(fd, before) != 0:
      return SiteTableComputation(reason: "fstat failed")
    if not S_ISREG(before.st_mode):
      return SiteTableComputation(reason: "not a regular file")
    var now: Timespec
    discard clock_gettime(CLOCK_REALTIME, now)
    let changedNs = (int64(now.tv_sec) - int64(before.st_ctim.tv_sec)) *
      1_000_000_000'i64 + (int64(now.tv_nsec) - int64(before.st_ctim.tv_nsec))
    if changedNs < settleNs:
      return SiteTableComputation(reason: "changed too recently")
    var ehdr: array[64, byte]
    if not preadFully(fd, addr ehdr[0], ehdr.len, 0):
      return SiteTableComputation(reason: "short ELF header")
    if ehdr[0] != 0x7f or ehdr[1] != byte('E') or ehdr[2] != byte('L') or
        ehdr[3] != byte('F') or ehdr[4] != 2 or ehdr[5] != 1:
      return SiteTableComputation(reason: "not a little-endian ELF64 file")
    let eType = readU16(ehdr, 0x10)
    if eType != etExec and eType != etDyn:
      return SiteTableComputation(reason: "not an executable or shared object")
    let phoff = readU64(ehdr, 0x20)
    let phentsize = int(readU16(ehdr, 0x36))
    let phnum = int(readU16(ehdr, 0x38))
    if phoff == 0 or phnum == 0 or phentsize != 56 or phnum > 4096:
      return SiteTableComputation(reason: "malformed program headers")
    var phdrs = newSeq[byte](phnum * phentsize)
    if not preadFully(fd, addr phdrs[0], phdrs.len, phoff):
      return SiteTableComputation(reason: "short program headers")
    let page = sysconf(SC_PAGESIZE)
    let pageSize = if page > 0: uint64(page) else: defaultPageSize
    let pageMask = pageSize - 1
    let reader: LinuxImageReader = proc(offset: uint64; dest: pointer;
                                        len: int): bool {.closure, raises: [].} =
      preadFully(fd, dest, len, offset)
    var image = SiteTableImage(dev: uint64(before.st_dev),
      ino: uint64(before.st_ino), size: uint64(before.st_size),
      mtimeSec: int64(before.st_mtim.tv_sec),
      mtimeNsec: int64(before.st_mtim.tv_nsec),
      ctimeSec: int64(before.st_ctim.tv_sec),
      ctimeNsec: int64(before.st_ctim.tv_nsec))
    for i in 0 ..< phnum:
      let at = i * phentsize
      if readU32(phdrs, at) != ptLoad or (readU32(phdrs, at + 4) and pfX) == 0:
        continue
      let pOffset = readU64(phdrs, at + 8)
      let pVaddr = readU64(phdrs, at + 16)
      let pFilesz = readU64(phdrs, at + 32)
      if pOffset > high(uint64) - pageMask or
          pFilesz > high(uint64) - pageMask - pOffset or
          pVaddr < (pOffset and pageMask):
        return SiteTableComputation(reason: "malformed executable segment")
      # The mapping the kernel makes of this segment, at load bias zero: its
      # file span rounded out to pages, starting at the page-rounded vaddr.
      let spanStart = pOffset and not pageMask
      let spanStop = (pOffset + pFilesz + pageMask) and not pageMask
      let mapping = LinuxExecutableMapping(
        start: uint(pVaddr - (pOffset - spanStart)),
        stop: uint(pVaddr - (pOffset - spanStart) + (spanStop - spanStart)),
        readable: true, executable: true, privateMapping: true,
        path: path, offset: uint(spanStart), inode: uint64(before.st_ino))
      let geometry = linuxImageCodeRangesFromReader(mapping,
        uint64(before.st_ino), reader, pageSize)
      if geometry.diagnostic != licrOk:
        return SiteTableComputation(reason: "code ranges: " & $geometry.diagnostic)
      var segment = SiteTableSegment(pOffset: pOffset, pVaddr: pVaddr,
                                     pFilesz: pFilesz)
      for r in geometry.ranges:
        segment.ranges.add (start: uint64(r.start), stop: uint64(r.stop))
        let len = int(r.stop - r.start)
        if len <= 0:
          continue
        # The range's link-time address equals its runtime address minus the
        # load bias, and the bias is zero here, so its file offset is
        # `pOffset + (start - pVaddr)`.
        var bytes = newSeq[byte](len)
        if not preadFully(fd, addr bytes[0], len,
                          pOffset + (uint64(r.start) - pVaddr)):
          return SiteTableComputation(reason: "short code read")
        let base = uint64(r.start)
        var found: seq[uint64] = @[]
        let collect = proc(site: LinuxSyscallSite): bool {.closure, raises: [].} =
          found.add base + uint64(site.offset)
          true
        visitLinuxX8664SyscallMemory(addr bytes[0], len, collect)
        segment.sites.add found
      image.segments.add segment
    var after: Stat
    if fstat(fd, after) != 0 or not sameIdentity(before, after):
      return SiteTableComputation(reason: "changed while it was read")
    SiteTableComputation(ok: true, image: image)

  proc createSealedSiteTableFile*(bytes: string): tuple[fd: cint; error: string] =
    ## A sealed memfd holding `bytes`. The caller owns the descriptor (it is
    ## close-on-exec); another process reaches it as `/proc/<pid>/fd/<fd>`.
    let fd = memfdCreate("io-mon-site-tables", MFD_CLOEXEC or MFD_ALLOW_SEALING)
    if fd < 0:
      return (-1.cint, "memfd_create failed: " & $strerror(errno))
    var done = 0
    while done < bytes.len:
      let n = write(fd, unsafeAddr bytes[done], bytes.len - done)
      if n <= 0:
        discard posix.close(fd)
        return (-1.cint, "writing the table failed: " & $strerror(errno))
      done += n
    if fcntlInt(fd, F_ADD_SEALS, requiredSeals) != 0:
      discard posix.close(fd)
      return (-1.cint, "sealing the table failed: " & $strerror(errno))
    (fd, "")

  proc closeSiteTableFile*(fd: cint) =
    ## Close a descriptor `createSealedSiteTableFile` returned. The memfd
    ## lives on while another process (a monitor host) holds its own
    ## descriptor of it.
    discard posix.close(fd)

  proc rawOk(r: int): bool {.inline.} = r >= 0

  type
    SiteTableView* = object
      ## A table file mapped read-only into the shim. Plain old data: the shim
      ## keeps one in a global the constructor writes.
      base*: pointer
      len*: int
      dev*, ino*: uint64
        ## Identity of the memfd, reported in `SiteTableServedDetail`.

  proc validSiteTableHeader(base: pointer; len: int): bool =
    if base == nil or len < siteTableHeaderLen:
      return false
    let b = cast[ptr UncheckedArray[byte]](base)
    for i in 0 ..< SiteTableMagic.len:
      if b[i] != byte(SiteTableMagic[i]):
        return false
    var v = 0'u32
    for i in 0 ..< 4: v = v or (uint32(b[8 + i]) shl (8 * i))
    var stamp = 0'u64
    for i in 0 ..< 8: stamp = stamp or (uint64(b[16 + i]) shl (8 * i))
    v == SiteTableVersion and stamp == siteTableScannerStamp

  proc sealedSiteTableIdentity*(fd: cint): tuple[ok: bool; dev, ino: uint64;
                                                size: int] =
    ## For the host: whether `fd` is a sealed table this build can use, and its
    ## identity. Does not map it.
    let seals = fcntlInt(fd, F_GET_SEALS, 0.cint)
    if seals < 0 or (seals and requiredSeals) != requiredSeals:
      return
    var st: Stat
    if fstat(fd, st) != 0 or st.st_size < siteTableHeaderLen:
      return
    var header: array[siteTableHeaderLen, byte]
    if not preadFully(fd, addr header[0], header.len, 0):
      return
    if not validSiteTableHeader(addr header[0], header.len):
      return
    (true, uint64(st.st_dev), uint64(st.st_ino), int(st.st_size))

  proc openSiteTableView*(path: string): SiteTableView =
    ## For the shim. Opens and maps `path` with raw system calls (none of the
    ## process's own libc entry points, so nothing here becomes evidence), and
    ## keeps it only when it is a sealed table of this build's scanner. Any
    ## failure leaves `base` nil: no table, every mapping is scanned.
    if path.len == 0 or path.len > 4000:
      return
    var cpath = path
    let fd = rawSyscall6(sysOpenat, atFdcwd, cast[int](cstring(cpath)),
                         int(O_RDONLY or O_CLOEXEC), 0, 0, 0)
    if not rawOk(fd):
      return
    defer: discard rawSyscall6(sysClose, fd, 0, 0, 0, 0, 0)
    let seals = rawSyscall6(sysFcntl, fd, int(F_GET_SEALS), 0, 0, 0, 0)
    if not rawOk(seals) or (seals and int(requiredSeals)) != int(requiredSeals):
      return
    var st: Stat
    if not rawOk(rawSyscall6(sysFstat, fd, cast[int](addr st), 0, 0, 0, 0)):
      return
    let size = int(st.st_size)
    if size < siteTableHeaderLen or size > 64 * 1024 * 1024:
      return
    let mapped = rawSyscall6(sysMmap, 0, size, int(PROT_READ), int(MAP_PRIVATE),
                             fd, 0)
    if mapped < 0 and mapped > -4096:
      return
    let base = cast[pointer](mapped)
    if not validSiteTableHeader(base, size):
      discard rawSyscall6(11, mapped, size, 0, 0, 0, 0)  # munmap
      return
    SiteTableView(base: base, len: size, dev: uint64(st.st_dev),
                  ino: uint64(st.st_ino))

  proc identityText*(view: SiteTableView): string =
    $view.dev & ":" & $view.ino

  proc codePagesUnwritten(ranges: openArray[LinuxAddressRange]): bool =
    ## True when no page of `ranges` has been written in this process: each is
    ## either not present (it will be read from the file when touched) or a
    ## present page-cache page of the file (`/proc/self/pagemap` bit 61,
    ## "file-page or shared-anon"; for a private file mapping a written page
    ## is an anonymous copy and has bit 61 clear, and a swapped page is always
    ## anonymous). See https://docs.kernel.org/admin-guide/mm/pagemap.html.
    ## Unavailable pagemap means "unknown", which is false.
    const presentBit = 63
    const swappedBit = 62
    const fileBit = 61
    var cpath = "/proc/self/pagemap"
    let fd = rawSyscall6(sysOpenat, atFdcwd, cast[int](cstring(cpath)),
                         int(O_RDONLY or O_CLOEXEC), 0, 0, 0)
    if not rawOk(fd):
      return false
    defer: discard rawSyscall6(sysClose, fd, 0, 0, 0, 0, 0)
    let page = uint(sysconf(SC_PAGESIZE))
    if page == 0:
      return false
    var buffer: array[512, uint64]
    for r in ranges:
      if r.stop <= r.start:
        continue
      var first = r.start div page
      let last = (r.stop - 1) div page
      while first <= last:
        let count = int(min(uint(buffer.len), last - first + 1))
        let n = rawSyscall6(sysPread64, fd, cast[int](addr buffer[0]), count * 8,
                            int(first * 8), 0, 0)
        if n != count * 8:
          return false
        for i in 0 ..< count:
          let entry = buffer[i]
          let present = (entry shr presentBit) and 1
          let swapped = (entry shr swappedBit) and 1
          let file = (entry shr fileBit) and 1
          if swapped != 0 or (present != 0 and file == 0):
            return false
        first += uint(count)
    true

  proc codeBytesEqualFile(mapping: LinuxExecutableMapping; st: Stat;
                          ranges: openArray[LinuxAddressRange]): bool =
    ## True when the bytes of `ranges` in memory equal the bytes at the same
    ## offsets of the file `mapping.path` names now, and that file kept the
    ## identity `st` (the table's) across the read. For a mapping whose maps
    ## device does not name the descriptor's (btrfs subvolumes, overlayfs):
    ## there the inode alone does not tell the mapped file from another file
    ## of the same superblock, so the decode's input is compared directly.
    ## The ranges lie inside `mapping` (`linuxImageCodeRangesFromReader`
    ## clips them to it), so each byte's file offset is its distance from the
    ## mapping's start plus the mapping's offset. Raw system calls, as for the
    ## pagemap: the image was already read through the probe, and this read
    ## must not become evidence a second time. Any failure is false.
    if mapping.path.len == 0 or mapping.path.len > 4000:
      return false
    var cpath = mapping.path
    let fd = rawSyscall6(sysOpenat, atFdcwd, cast[int](cstring(cpath)),
                         int(O_RDONLY or O_CLOEXEC), 0, 0, 0)
    if not rawOk(fd):
      return false
    defer: discard rawSyscall6(sysClose, fd, 0, 0, 0, 0, 0)
    var now: Stat
    if not rawOk(rawSyscall6(sysFstat, fd, cast[int](addr now), 0, 0, 0, 0)) or
        not sameIdentity(now, st):
      return false
    var buffer: array[16384, byte]
    for r in ranges:
      if r.stop <= r.start:
        continue
      if r.start < mapping.start or r.stop > mapping.stop:
        return false
      var at = r.start
      while at < r.stop:
        let count = int(min(uint(buffer.len), r.stop - at))
        let offset = at - mapping.start + mapping.offset
        var done = 0
        while done < count:
          let n = rawSyscall6(sysPread64, fd, cast[int](addr buffer[done]),
                              count - done, int(offset) + done, 0, 0)
          if n <= 0:
            return false
          done += n
        if not equalMem(addr buffer[0], cast[pointer](at), count):
          return false
        at += uint(count)
    # A write during the read would change the file's mtime and ctime.
    rawOk(rawSyscall6(sysFstat, fd, cast[int](addr now), 0, 0, 0, 0)) and
      sameIdentity(now, st)

  proc parseMapsDevice(text: string; major, minor: var uint64): bool =
    let colon = text.find(':')
    if colon <= 0:
      return false
    try:
      major = uint64(parseHexInt(text[0 ..< colon]))
      minor = uint64(parseHexInt(text[colon + 1 .. ^1]))
      true
    except ValueError:
      false

  proc statDeviceMatchesMaps(stDev: uint64; mapsDevice: string): bool =
    ## glibc's `major`/`minor` of a `dev_t`, compared with the `major:minor`
    ## text `/proc/self/maps` printed for the mapping.
    var major, minor: uint64
    if not parseMapsDevice(mapsDevice, major, minor):
      return false
    let devMajor = ((stDev shr 8) and 0xfff'u64) or
      ((stDev shr 32) and 0xfffff000'u64)
    let devMinor = (stDev and 0xff'u64) or ((stDev shr 12) and 0xffffff00'u64)
    devMajor == major and devMinor == minor

  proc serveSitesFromTable*(view: SiteTableView;
                            mapping: LinuxExecutableMapping;
                            st: Stat;
                            ranges: openArray[LinuxAddressRange];
                            visitor: proc(site: LinuxSyscallSite): bool
                              {.closure, raises: [].}): bool {.raises: [].} =
    ## For the shim. When `view` holds a table for the file behind `mapping`
    ## (`st` is the `fstat` of the file whose section table produced `ranges`)
    ## and every condition in the module header holds, present each of its
    ## sites to `visitor` exactly as `visitLinuxX8664SyscallMemory` would over
    ## `ranges`, and return true. Otherwise present nothing and return false;
    ## the caller then scans.
    if view.base == nil:
      return false
    # Whether `/proc/self/maps` names the descriptor's device. It prints the
    # superblock's device, and `stat` reports the same one on most file
    # systems; there, with the inode, it proves the descriptor's file is the
    # mapped one. btrfs reports each subvolume's own device in `stat`, and
    # an overlayfs reports the layer's, while maps still prints the
    # superblock's, so on those the identity cannot bind the two and the
    # bytes have to (`codeBytesEqualFile`, below).
    let deviceBound = statDeviceMatchesMaps(uint64(st.st_dev), mapping.device)
    let b = cast[ptr UncheckedArray[byte]](view.base)
    let total = view.len
    template u32(at: int): uint32 =
      (uint32(b[at]) or (uint32(b[at + 1]) shl 8) or
        (uint32(b[at + 2]) shl 16) or (uint32(b[at + 3]) shl 24))
    template u64(at: int): uint64 =
      (uint64(u32(at)) or (uint64(u32(at + 4)) shl 32))
    let imageCount = int(u32(12))
    var at = siteTableHeaderLen
    let page = uint64(sysconf(SC_PAGESIZE))
    if page == 0 or (page and (page - 1)) != 0:
      return false
    let pageMask = page - 1
    for _ in 0 ..< imageCount:
      if at + imageHeaderLen > total:
        return false
      let dev = u64(at)
      let ino = u64(at + 8)
      let size = u64(at + 16)
      let mtimeSec = cast[int64](u64(at + 24))
      let mtimeNsec = cast[int64](u64(at + 32))
      let ctimeSec = cast[int64](u64(at + 40))
      let ctimeNsec = cast[int64](u64(at + 48))
      let segmentCount = int(u32(at + 56))
      at += imageHeaderLen
      let matches = dev == uint64(st.st_dev) and ino == uint64(st.st_ino) and
        ino == mapping.inode and size == uint64(st.st_size) and
        mtimeSec == int64(st.st_mtim.tv_sec) and
        mtimeNsec == int64(st.st_mtim.tv_nsec) and
        ctimeSec == int64(st.st_ctim.tv_sec) and
        ctimeNsec == int64(st.st_ctim.tv_nsec)
      for _ in 0 ..< segmentCount:
        if at + segmentHeaderLen > total:
          return false
        let pOffset = u64(at)
        let pVaddr = u64(at + 8)
        let pFilesz = u64(at + 16)
        let rangeCount = int(u32(at + 24))
        let siteCount = int(u32(at + 28))
        at += segmentHeaderLen
        if rangeCount < 0 or siteCount < 0 or
            rangeCount > (total - at) div 16:
          return false
        let rangesAt = at
        at += rangeCount * 16
        if siteCount > (total - at) div 8:
          return false
        let sitesAt = at
        at += siteCount * 8
        if not matches:
          continue
        # The segment this mapping belongs to, by the rule
        # `linuxImageCodeRangesFromReader` applies.
        if pOffset > high(uint64) - pageMask or
            pFilesz > high(uint64) - pageMask - pOffset:
          return false
        let spanStart = pOffset and not pageMask
        let spanStop = (pOffset + pFilesz + pageMask) and not pageMask
        let mappingOffset = uint64(mapping.offset)
        if mappingOffset < spanStart or mappingOffset >= spanStop:
          continue
        let bias = uint64(mapping.start) - mappingOffset + pOffset - pVaddr
        # The decode must start and stop where the scan's would.
        if rangeCount != ranges.len:
          return false
        for i in 0 ..< rangeCount:
          let start = u64(rangesAt + i * 16) + bias
          let stop = u64(rangesAt + i * 16 + 8) + bias
          if uint64(ranges[i].start) != start or uint64(ranges[i].stop) != stop:
            return false
        # Memory must still hold the file's bytes.
        if not codePagesUnwritten(ranges):
          return false
        if not deviceBound and not codeBytesEqualFile(mapping, st, ranges):
          return false
        # Sites are stored in scan order; present them as the scan would. A
        # site outside the ranges cannot come from the producer, so the table
        # is refused before anything is presented.
        for i in 0 ..< siteCount:
          let address = u64(sitesAt + i * 8) + bias
          var inside = false
          for r in ranges:
            if address >= uint64(r.start) and address + 2 < uint64(r.stop):
              inside = true
              break
          if not inside:
            return false
        for i in 0 ..< siteCount:
          let address = uint(u64(sitesAt + i * 8) + bias)
          var rangeStart = uint(0)
          for r in ranges:
            if address >= r.start and address < r.stop:
              rangeStart = r.start
              break
          let site = LinuxSyscallSite(address: address,
            offset: int(address - rangeStart),
            nextByte: cast[ptr byte](address + 2)[])
          if not visitor(site):
            break
        return true
    false

  proc imageCodeRangesWithIdentity*(mapping: LinuxExecutableMapping):
      tuple[ranges: LinuxImageCodeRanges; st: Stat; statOk: bool] {.raises: [].} =
    ## `linuxImageCodeRanges(mapping)`, through the same calls, also returning
    ## the `fstat` of the file the section table was read from, so a table is
    ## matched against exactly the file that gave the code ranges.
    if mapping.path.len == 0 or mapping.path[0] != '/':
      result.ranges = LinuxImageCodeRanges(diagnostic: licrNotFileBacked)
      return
    let fd = posix.open(cstring(mapping.path), O_RDONLY or O_CLOEXEC)
    if fd < 0:
      result.ranges = LinuxImageCodeRanges(diagnostic: licrOpenFailed,
                                           osErrno: errno)
      return
    defer: discard posix.close(fd)
    if fstat(fd, result.st) != 0:
      result.ranges = LinuxImageCodeRanges(diagnostic: licrOpenFailed,
                                           osErrno: errno)
      return
    result.statOk = true
    var readErrno: cint = 0
    let reader: LinuxImageReader = proc(offset: uint64; dest: pointer;
                                        len: int): bool {.closure, raises: [].} =
      var done = 0
      while done < len:
        let n = pread(fd, cast[pointer](cast[uint](dest) + uint(done)),
                      len - done, Off(offset + uint64(done)))
        if n <= 0:
          if n < 0: readErrno = errno
          return false
        done += int(n)
      true
    let page = sysconf(SC_PAGESIZE)
    let pageSize = if page > 0: uint64(page) else: defaultPageSize
    result.ranges = linuxImageCodeRangesFromReader(mapping,
      uint64(result.st.st_ino), reader, pageSize)
    if result.ranges.diagnostic == licrMalformed and readErrno != 0:
      result.ranges.osErrno = readErrno
