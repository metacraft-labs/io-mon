/*
 * macOS tree-lifetime guard: the kernel census (see macos_tree_guard.nim for
 * the contract and the soundness argument). This file only gathers facts.
 * Every decision about what a fact means for the capture is made by the Nim
 * caller, which fails closed on anything but a measured, fully classified,
 * member-free census.
 *
 * One sweep:
 *   1. ONE sysctl(KERN_PROC_ALL) snapshot of every process: pid, state, flags,
 *      effective uid, start time. The kernel fills it under the process-list
 *      lock, so it is a single point-in-time listing.
 *   2. Skip what cannot be a live descendant: the caller itself, pid 0,
 *      zombies, processes already exiting (P_WEXIT), and processes that started
 *      strictly before the monitored root. "Before" is measured on the
 *      MONOTONIC clock (proc_pid_rusage's ri_proc_start_abstime, mach absolute
 *      time), never the wall clock: kp_proc.p_starttime is wall-clock time, and
 *      a wall clock stepped backwards after the root started would date a real
 *      descendant before its root. A process whose monotonic start cannot be
 *      read is kept.
 *   3. For each remaining (young) process, read its live argument/environment
 *      area with sysctl(KERN_PROCARGS2) and look for either run needle as a
 *      WHOLE NUL-separated string anywhere in it. The area is the process's
 *      own memory, which it may overwrite (setproctitle-style); the host's
 *      tree-ledger liveness check (iomon_tg_alive) covers that case.
 *   4. A young process whose strings cannot be read is re-examined with
 *      sysctl(KERN_PROC_PID). If it is gone, a zombie, exiting, or a different
 *      process (start time changed), it VANISHED during the sweep: it may have
 *      been a member that created a child after the snapshot. If it is alive
 *      and runs as another user, it is a non-member: the kernel never shows
 *      another user's strings to an unprivileged caller, and such a process
 *      cannot be carrying this run's shim (see the Nim module). Alive, same
 *      user (or caller is root), unreadable (caught mid-fork or mid-exec):
 *      unresolved.
 *   5. A vanished or unresolved process whose snapshot parent is not launchd
 *      is classified through that parent (see `classify`): the child of a
 *      non-member is a non-member. What is still vanished or unresolved after
 *      that makes the sweep inconclusive.
 */
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef P_WEXIT
#define P_WEXIT 0x00002000
#endif

#define IOMON_TG_COMM_LEN 17

typedef struct {
  int32_t pid;
  int32_t reason; /* 0 = member, 1 = vanished, 2 = unreadable,
                      3 = live tree-ledger entry */
  char comm[IOMON_TG_COMM_LEN];
} iomon_tg_hit;

static uint64_t tv_usec(const struct timeval *tv) {
  return (uint64_t)tv->tv_sec * 1000000ull + (uint64_t)tv->tv_usec;
}

/* Monotonic start time of `pid` (mach absolute time, as recorded by the
 * kernel at process creation). 0 = unknown: the process is gone, or the
 * caller may not read it (another user's process, for an unprivileged
 * caller). Unlike p_starttime it cannot be moved by a wall-clock step. */
uint64_t iomon_tg_start_abs(int32_t pid) {
  if (pid <= 0)
    return 0;
  struct rusage_info_v2 ri;
  memset(&ri, 0, sizeof(ri));
  if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ri) != 0)
    return 0;
  return ri.ri_proc_start_abstime;
}

/* Kernel start time of `pid` in microseconds since the epoch. 0 = unknown. */
uint64_t iomon_tg_start_usec(int32_t pid) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  struct kinfo_proc kp;
  size_t size = sizeof(kp);
  memset(&kp, 0, sizeof(kp));
  if (sysctl(mib, 4, &kp, &size, NULL, 0) != 0 || size == 0)
    return 0;
  return tv_usec(&kp.kp_proc.p_starttime);
}

#ifdef IOMON_TG_FAULT_TEST
/* Wall-step seam: every wall-clock process start time the census reads
 * during a sweep is moved back by this much, which is what a wall clock
 * stepped backwards after the root started does to the processes created
 * after the step. The root's own start, taken at the spawn, is unaffected.
 * A census that dated processes by the wall clock would then prune every
 * descendant as "older than the root". */
int64_t iomon_tg_fault_wall_shift_usec = 0;
#define TG_WALL_SHIFT ((uint64_t)iomon_tg_fault_wall_shift_usec)
#else
#define TG_WALL_SHIFT 0ull
#endif

/* The wall-clock start time of a snapshot entry, as the census sees it. */
static uint64_t observed_start_usec(const struct kinfo_proc *p) {
  return tv_usec(&p->kp_proc.p_starttime) - TG_WALL_SHIFT;
}

/* 1 if `pid` is still the same live, non-exiting process. */
static int still_alive(int32_t pid, uint64_t start_usec) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  struct kinfo_proc kp;
  size_t size = sizeof(kp);
  memset(&kp, 0, sizeof(kp));
  if (sysctl(mib, 4, &kp, &size, NULL, 0) != 0 || size == 0)
    return 0;
  if (kp.kp_proc.p_stat == SZOMB || (kp.kp_proc.p_flag & P_WEXIT))
    return 0;
  return observed_start_usec(&kp) == start_usec;
}

/* Does the KERN_PROCARGS2 image carry either needle as a whole NUL-separated
 * string? Layout: int argc, exec path, NUL padding, argv[0..argc-1], then the
 * environment strings, then the loader's "apple" strings. Every string after
 * the argc word is scanned, argv included: skipping argv by count misaligns
 * when argv[0] is empty (its NUL is eaten as padding) and would then skip the
 * first environment string; scanning everything cannot miss one, and a needle
 * in argv is still a needle (it fails closed). A process whose environment
 * the kernel withholds (platform binaries, while SIP is on) yields argv
 * only. */
static int carries_needle(const char *buf, size_t n, const char *n1,
                          size_t n1len, const char *n2, size_t n2len) {
  if (n < sizeof(int))
    return 0;
  size_t i = sizeof(int);
  while (i < n) {
    size_t start = i;
    while (i < n && buf[i] != '\0') i++;
    size_t len = i - start;
    if (len == n1len && n1len > 0 && memcmp(buf + start, n1, len) == 0)
      return 1;
    if (len == n2len && n2len > 0 && memcmp(buf + start, n2, len) == 0)
      return 1;
    i++;
  }
  return 0;
}

#ifdef IOMON_TG_FAULT_TEST
/* Test entry to the needle scan, for crafted KERN_PROCARGS2 images. */
int iomon_tg_test_carries_needle(const char *buf, size_t n, const char *n1,
                                  size_t n1len) {
  return carries_needle(buf, n, n1, n1len, NULL, 0);
}

int iomon_tg_fault_census = 0;
/* Vanish seam: between the snapshot and the first strings read, release this
 * pid with SIGUSR1 and wait (at most 2 s) until it has exited. A test member
 * forks on that signal and exits, so the census meets a REAL member that
 * vanished after the snapshot and left a child the snapshot does not list.
 * It fires once per pid, so only the first sweep of a capture sees it. It
 * can only make a sweep less conclusive, never more. */
int32_t iomon_tg_fault_vanish_pid = 0;
static int32_t tg_fault_vanished_pid = 0;
/* How the census classified the released pid (a TG_* value, -1 = not met),
 * so the test can tell "this sweep distrusted the vanished member" apart
 * from "some unrelated process kept this sweep inconclusive". */
int iomon_tg_fault_vanish_verdict = -1;
static void tg_fault_vanish(void) {
  int32_t pid = iomon_tg_fault_vanish_pid;
  if (pid <= 0 || pid == tg_fault_vanished_pid)
    return;
  tg_fault_vanished_pid = pid;
  iomon_tg_fault_vanish_verdict = -1;
  uint64_t start = iomon_tg_start_usec(pid);
  if (start == 0 || kill(pid, SIGUSR1) != 0)
    return;
  start -= TG_WALL_SHIFT;
  for (int i = 0; i < 2000 && still_alive(pid, start); i++)
    usleep(1000);
}
#endif

enum {
  TG_UNKNOWN = 0,
  TG_NONMEMBER,   /* cannot be carrying this run's shim */
  TG_MEMBER,      /* carries a needle */
  TG_VANISHED,    /* gone between the snapshot and its read */
  TG_UNREADABLE,  /* alive, same user, strings refused */
  TG_DEAD,        /* zombie or exiting at the snapshot */
  TG_BUSY         /* being classified (cycle guard) */
};

typedef struct {
  const struct kinfo_proc *procs;
  size_t count;
  int32_t *by_pid;      /* indices sorted by pid */
  unsigned char *memo;
  unsigned char *age;   /* per entry: 0 not yet known, 1 young, 2 older */
  int32_t self;
  uint64_t root_start_abs;
  const char *n1, *n2;
  size_t n1len, n2len;
  char *args;
  int argmax;
  uid_t me;
  int young;
} tg_ctx;

/* BSD qsort_r: the context comes first, so no global (concurrent monitors
    may finish on different threads). */
static int by_pid_cmp(void *ctx, const void *a, const void *b) {
  const struct kinfo_proc *procs = ctx;
  int32_t pa = procs[*(const int32_t *)a].kp_proc.p_pid;
  int32_t pb = procs[*(const int32_t *)b].kp_proc.p_pid;
  return (pa > pb) - (pa < pb);
}

static long find_pid(const tg_ctx *c, int32_t pid) {
  size_t lo = 0, hi = c->count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int32_t p = c->procs[c->by_pid[mid]].kp_proc.p_pid;
    if (p == pid) return c->by_pid[mid];
    if (p < pid) lo = mid + 1; else hi = mid;
  }
  return -1;
}

/* Could snapshot entry `idx` be a descendant of the root, by start time?
 * Only a process whose MONOTONIC start is known and strictly earlier than the
 * root's is "older" and pruned. A pid recycled between the snapshot and this
 * read reports the newer process's start, which is later, so it is kept. */
static int is_young(tg_ctx *c, long idx) {
  if (c->age[idx] == 0) {
    uint64_t start = c->root_start_abs == 0 ? 0
                    : iomon_tg_start_abs(c->procs[idx].kp_proc.p_pid);
    c->age[idx] = (start != 0 && start < c->root_start_abs) ? 2 : 1;
  }
  return c->age[idx] == 1;
}

/*
 * Classify snapshot entry `idx`.
 *
 * A process whose own strings cannot be read (it vanished, or it is caught
 * mid-fork or mid-exec) is classified through its PARENT when the snapshot
 * names one other than launchd: on macOS an orphan is reparented to launchd
 * (pid 1) and to nothing else, so a snapshot ppid other than 1 is the process
 * that created it. A child inherits its creator's environment, and the
 * needles reach a process only through the monitored root's spawn
 * environment, so the child of a NON-member is a non-member, and so is
 * everything that child creates. (A member that forks and then re-execs with
 * the needles removed would make that wrong for the child, but such an exec
 * runs an image that does not report to this run, which the unmonitored
 * subtree accounting already grades incomplete.) An orphan, or a process whose
 * parent is itself unresolved, stays unresolved.
 */
static int classify(tg_ctx *c, long idx, int depth) {
  if (c->memo[idx] != TG_UNKNOWN && c->memo[idx] != TG_BUSY)
    return c->memo[idx];
  if (c->memo[idx] == TG_BUSY || depth > 64)
    return TG_UNREADABLE;
  const struct kinfo_proc *p = &c->procs[idx];
  int32_t pid = p->kp_proc.p_pid;
  int result;
  if (pid <= 0 || pid == c->self) {
    result = TG_NONMEMBER;
  } else if (p->kp_proc.p_stat == SZOMB || (p->kp_proc.p_flag & P_WEXIT)) {
    result = TG_DEAD;
  } else if (!is_young(c, idx)) {
    result = TG_NONMEMBER;   /* started before the root: not a descendant */
  } else {
    c->young++;
    int amib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t alen = (size_t)c->argmax;
    if (sysctl(amib, 3, c->args, &alen, NULL, 0) == 0) {
      result = carries_needle(c->args, alen, c->n1, c->n1len, c->n2, c->n2len)
                    ? TG_MEMBER : TG_NONMEMBER;
    } else if (!still_alive(pid, observed_start_usec(p))) {
      result = TG_VANISHED;
    } else if (c->me != 0 && p->kp_eproc.e_ucred.cr_uid != c->me) {
      result = TG_NONMEMBER;  /* another user's process: never this run's shim */
    } else {
      result = TG_UNREADABLE;
    }
    if (result == TG_VANISHED || result == TG_UNREADABLE) {
      int32_t ppid = p->kp_eproc.e_ppid;
      if (ppid > 1) {
        long j = find_pid(c, ppid);
        if (j >= 0) {
          c->memo[idx] = TG_BUSY;
          if (classify(c, j, depth + 1) == TG_NONMEMBER)
            result = TG_NONMEMBER;
        }
      }
    }
  }
  c->memo[idx] = (unsigned char)result;
#ifdef IOMON_TG_FAULT_TEST
  if (pid > 0 && pid == tg_fault_vanished_pid)
    iomon_tg_fault_vanish_verdict = result;
#endif
  return result;
}

static void add_hit(iomon_tg_hit *hits, int cap, int *n_hits,
                    const struct kinfo_proc *p, int reason) {
  if (*n_hits < cap) {
    iomon_tg_hit *h = &hits[*n_hits];
    h->pid = p->kp_proc.p_pid;
    h->reason = reason;
    memset(h->comm, 0, sizeof(h->comm));
    memcpy(h->comm, p->kp_proc.p_comm,
            strnlen(p->kp_proc.p_comm, IOMON_TG_COMM_LEN - 1));
  }
  (*n_hits)++;
}

/*
 * Is tree-ledger entry (pid, start_usec) a live process in the snapshot?
 * Matched against the SAME snapshot as the census, so both answers are about
 * the same instant. The recorded start time is the kernel's own
 * (proc_pidinfo pbi_start, which is kp_proc.p_starttime) and is compared
 * exactly, unshifted: a recycled pid has a different start and is not this
 * entry. An entry whose start the writer could not read (0) matches any live
 * process with that pid that is not provably older than the root, which can
 * only err towards "live".
 */
static long ledger_live(tg_ctx *c, int32_t pid, uint64_t start_usec) {
  long j = find_pid(c, pid);
  if (j < 0)
    return -1;
  const struct kinfo_proc *p = &c->procs[j];
  if (p->kp_proc.p_stat == SZOMB || (p->kp_proc.p_flag & P_WEXIT))
    return -1;
  if (start_usec != 0)
    return tv_usec(&p->kp_proc.p_starttime) == start_usec ? j : -1;
  return is_young(c, j) ? j : -1;
}

/*
 * Returns 0 on a completed sweep, otherwise the errno of the failed census
 * call. `hits` receives every member, vanished and unresolved pid, in snapshot
 * order and tagged with its reason (0 member, 1 vanished, 2 unreadable), then
 * every tree-ledger entry that is live in the same snapshot (reason 3), up to
 * `cap`; `*n_hits` is the full count (it may exceed `cap`). `*young` counts
 * the processes the start-time prune kept and the census read.
 */
int iomon_tg_sweep(int32_t self, uint64_t root_start_abs, const char *n1,
                    size_t n1len, const char *n2, size_t n2len,
                    const int32_t *ledger_pids, const uint64_t *ledger_starts,
                    int ledger_n,
                    iomon_tg_hit *hits, int cap, int *n_hits, int *young) {
  *n_hits = 0;
  *young = 0;
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  u_int mib_len = 3;
#ifdef IOMON_TG_FAULT_TEST
  if (iomon_tg_fault_census) {
    /* A real call that really fails: an unknown KERN_PROC selector. */
    mib[2] = 0x7fff;
    mib_len = 4;
  }
#endif
  struct kinfo_proc *procs = NULL;
  size_t size = 0;
  int err = 0;
  for (int attempt = 0; attempt < 8; attempt++) {
    size = 0;
    if (sysctl(mib, mib_len, NULL, &size, NULL, 0) != 0) {
      err = errno ? errno : EIO;
      break;
    }
    size += size / 4 + 16 * sizeof(struct kinfo_proc);
    free(procs);
    procs = malloc(size);
    if (!procs) {
      err = ENOMEM;
      break;
    }
    if (sysctl(mib, mib_len, procs, &size, NULL, 0) == 0) {
      err = 0;
      break;
    }
    err = errno ? errno : EIO;
    if (err != ENOMEM)
      break;
  }
  if (err != 0) {
    free(procs);
    return err;
  }
#ifdef IOMON_TG_FAULT_TEST
  tg_fault_vanish();
#endif
  tg_ctx c;
  memset(&c, 0, sizeof(c));
  c.procs = procs;
  c.count = size / sizeof(struct kinfo_proc);
  c.self = self;
  c.root_start_abs = root_start_abs;
  c.n1 = n1; c.n1len = n1len; c.n2 = n2; c.n2len = n2len;
  c.me = geteuid();
  int amib[2] = {CTL_KERN, KERN_ARGMAX};
  size_t argmax_len = sizeof(c.argmax);
  if (sysctl(amib, 2, &c.argmax, &argmax_len, NULL, 0) != 0 || c.argmax <= 0)
    c.argmax = 1024 * 1024;
  c.by_pid = malloc((c.count ? c.count : 1) * sizeof(int32_t));
  c.memo = calloc(c.count ? c.count : 1, 1);
  c.age = calloc(c.count ? c.count : 1, 1);
  c.args = malloc((size_t)c.argmax);
  if (!c.by_pid || !c.memo || !c.age || !c.args) {
    free(c.by_pid); free(c.memo); free(c.age); free(c.args); free(procs);
    return ENOMEM;
  }
  for (size_t k = 0; k < c.count; k++) c.by_pid[k] = (int32_t)k;
  qsort_r(c.by_pid, c.count, sizeof(int32_t), procs, by_pid_cmp);

  for (size_t k = 0; k < c.count; k++) {
    /* classify() applies the start-time prune itself, after the cheap
        self/zombie checks, so an older process costs one rusage read. */
    int r = classify(&c, (long)k, 0);
    int reason = r == TG_MEMBER ? 0 : r == TG_VANISHED ? 1
                : r == TG_UNREADABLE ? 2 : -1;
    if (reason >= 0)
      add_hit(hits, cap, n_hits, &procs[k], reason);
  }
  for (int e = 0; e < ledger_n; e++) {
    long j = ledger_live(&c, ledger_pids[e], ledger_starts[e]);
    if (j >= 0 && procs[j].kp_proc.p_pid != self)
      add_hit(hits, cap, n_hits, &procs[j], 3);
  }
  *young = c.young;
  free(c.by_pid); free(c.memo); free(c.age); free(c.args); free(procs);
  return 0;
}
