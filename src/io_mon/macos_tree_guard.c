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
 *      non-member is a non-member. A parent that is itself exiting (or a
 *      zombie) is classified through ITS parent in turn (`creator_class`).
 *      An unresolved process the parent chain cannot classify is then
 *      classified by its CREATOR's kernel unique id, which survives
 *      reparenting (`creator_predates_root`): an orphan whose creator is
 *      older than the root is a non-member. What is still
 *      vanished or unresolved after that makes the sweep inconclusive.
 */
#include <errno.h>
#include <stddef.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
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

/* Slow-strings seam: a process whose p_comm equals this name has its
 * KERN_PROCARGS2 read refused, as the kernel refuses it for a process still
 * between fork and exec or not yet scheduled, until this many milliseconds
 * after its kernel start time. That is what a heavily loaded host does to a
 * young process (issue: young processes the guard cannot classify under
 * host load), made deterministic. The process is then alive, same-user and
 * unreadable, exactly the state the census calls unresolved. Refusing a read
 * can only make a sweep less conclusive. */
char iomon_tg_fault_slow_comm[IOMON_TG_COMM_LEN] = {0};
int64_t iomon_tg_fault_slow_ms = 0;
static int tg_fault_strings_refused(const struct kinfo_proc *p) {
  if (iomon_tg_fault_slow_comm[0] == '\0' || iomon_tg_fault_slow_ms <= 0)
    return 0;
  if (strncmp(p->kp_proc.p_comm, iomon_tg_fault_slow_comm,
              IOMON_TG_COMM_LEN - 1) != 0)
    return 0;
  struct timeval now;
  gettimeofday(&now, NULL);
  uint64_t start = tv_usec(&p->kp_proc.p_starttime);
  uint64_t at = tv_usec(&now);
  return at < start + (uint64_t)iomon_tg_fault_slow_ms * 1000ull;
}

/* Exiting seam: this pid is classified as exiting (TG_DEAD) unless its
 * strings carry a needle, standing in for a parent caught in exit with a
 * child it has not yet handed to launchd, a window real timing hits only by
 * chance. A member is never affected, so the seam cannot hide one; on a
 * non-member it changes only how its children are classified. */
int32_t iomon_tg_fault_exiting_pid = 0;
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
  uint64_t root_uniqueid;  /* 0 = unknown: the creator rule is off */
  uint64_t self_uniqueid;  /* 0 = unknown: the creator rule is off */
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
/*
 * THE CREATOR'S UNIQUE ID. Every process has a 64-bit kernel unique id,
 * assigned from a counter at creation and never reused, and the kernel also
 * keeps the unique id of its parent as of its last fork or exec
 * (`p_puniqueid`). Handing an orphan to launchd does not rewrite it, but an
 * exec does: measured on macOS 26, an orphan that execs after its creator
 * exited reads launchd's id, 1, exactly like a job launchd started itself. So
 * id 1 proves nothing (a launchd job and a re-exec'd orphan of the tree look
 * the same), and only an id of a process OLDER than the root is used. It is
 * read with
 * proc_pidinfo flavor PROC_PIDUNIQIDENTIFIERINFO (17), which works for any
 * same-user process without privilege but is declared only in xnu's private
 * header, so the flavor and the layout are copied here from
 *   https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
 * (struct proc_uniqidentifierinfo). The static asserts pin the offsets read;
 * a kernel that answers with fewer bytes than reach `p_puniqueid`, or fails,
 * leaves the process unresolved (fail closed).
 */
#define IOMON_TG_PIDUNIQIDENTIFIERINFO 17
struct iomon_tg_uniqidentifierinfo {
  uint8_t p_uuid[16];          /* UUID of the main executable */
  uint64_t p_uniqueid;         /* 64-bit unique id of the process */
  uint64_t p_puniqueid;        /* unique id of the process that created it */
  int32_t p_idversion;         /* pid version */
  int32_t p_orig_ppidversion;  /* original parent pid version */
  uint64_t p_reserve2;
  uint64_t p_reserve3;
};
_Static_assert(offsetof(struct iomon_tg_uniqidentifierinfo, p_uniqueid) == 16,
  "p_uniqueid offset (xnu proc_uniqidentifierinfo)");
_Static_assert(offsetof(struct iomon_tg_uniqidentifierinfo, p_puniqueid) == 24,
  "p_puniqueid offset (xnu proc_uniqidentifierinfo)");
_Static_assert(sizeof(struct iomon_tg_uniqidentifierinfo) == 56,
  "proc_uniqidentifierinfo size (xnu)");

/* (unique id, creator's unique id) of `pid`; 1 when read, 0 otherwise. The
 * buffer is larger than the struct so a kernel with a longer one still
 * answers; only the bytes it says it wrote are used. */
int iomon_tg_unique_ids(int32_t pid, uint64_t *uniq, uint64_t *puniq) {
  union {
    struct iomon_tg_uniqidentifierinfo info;
    unsigned char raw[256];
  } u;
  memset(&u, 0, sizeof(u));
  if (pid <= 0)
    return 0;
  int n = proc_pidinfo(pid, IOMON_TG_PIDUNIQIDENTIFIERINFO, 0, &u, sizeof(u));
  if (n < (int)(offsetof(struct iomon_tg_uniqidentifierinfo, p_puniqueid) +
                sizeof(uint64_t)))
    return 0;
  *uniq = u.info.p_uniqueid;
  *puniq = u.info.p_puniqueid;
  return 1;
}

#ifdef IOMON_TG_FAULT_TEST
/* Creator-id seam: when set, the creator rule is skipped, so a test can show
 * a case the rule (and only the rule) classifies. */
int iomon_tg_fault_no_creator_rule = 0;
#endif

/*
 * Is live, unreadable snapshot entry `idx` provably outside the tree by its
 * creator? Yes when the parent recorded at its last fork or exec is older
 * than the root (its id is below the root's) and is neither launchd (id 1,
 * see above) nor the guard's own process (which spawned the root with the
 * needles). Ids are assigned in creation order, so that parent was created
 * before the root and is not a descendant, and the child of a non-member is a
 * non-member. A tree process's parent at a fork or exec is a tree process (id
 * above the root's), launchd, or the guard (the root only, reaped before any
 * sweep). The one exception is a debugger older than the root that attached
 * to a tree process (macOS makes the tracer the parent) when it exec'd; that
 * process becomes readable, carrying the needles, once its exec completes.
 * The ids are read between two liveness checks of the same (pid, start), so
 * they belong to this process, not a recycled pid. Anything else, including
 * an orphan whose creator is younger than the root and gone, and a launchd
 * job, stays unresolved.
 */
static int creator_predates_root(tg_ctx *c, long idx) {
#ifdef IOMON_TG_FAULT_TEST
  if (iomon_tg_fault_no_creator_rule)
    return 0;
#endif
  const struct kinfo_proc *p = &c->procs[idx];
  int32_t pid = p->kp_proc.p_pid;
  uint64_t uniq = 0, puniq = 0;
  if (!iomon_tg_unique_ids(pid, &uniq, &puniq))
    return 0;
  if (!still_alive(pid, observed_start_usec(p)))
    return 0;
  return puniq > 1 && c->root_uniqueid != 0 && c->self_uniqueid != 0 &&
    puniq < c->root_uniqueid && puniq != c->self_uniqueid &&
    uniq != c->root_uniqueid;
}

static int classify(tg_ctx *c, long idx, int depth);

/*
 * The class of the process that created a child, starting from the child's
 * snapshot parent `j`: its own class, unless it is exiting or a zombie
 * (TG_DEAD). An exiting parent still names its children (XNU hands them to
 * launchd during exit, so a snapshot can catch a child whose parent is
 * mid-exit), but its strings can no longer be read. It is then classified
 * through ITS parent by the same rule: the child of a non-member is a
 * non-member, whether or not it is still running, so a non-member ancestor
 * makes the whole chain below it non-members. The walk stops, unresolved, at
 * launchd (pid 1, which adopts orphans, so it created nothing it names) and
 * at the guard's own process: the host spawned the root with the needles,
 * so its children are the one place the needles start, and "the child of a
 * non-member" does not hold there. (The root has been reaped before any
 * sweep, so no live descendant names the host or the root as its parent;
 * the stop is a guard against a caller that breaks that order.)
 */
static int creator_class(tg_ctx *c, long j, int depth) {
  for (int hop = 0; hop < 64; hop++) {
    int r = classify(c, j, depth + hop);
    if (r != TG_DEAD)
      return r;
    int32_t ppid = c->procs[j].kp_eproc.e_ppid;
    if (ppid <= 1 || ppid == c->self)
      return TG_UNREADABLE;
    long k = find_pid(c, ppid);
    if (k < 0)
      return TG_UNREADABLE;
    j = k;
  }
  return TG_UNREADABLE;
}

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
    int read_ok = sysctl(amib, 3, c->args, &alen, NULL, 0) == 0;
#ifdef IOMON_TG_FAULT_TEST
    if (read_ok && tg_fault_strings_refused(p))
      read_ok = 0;
#endif
    if (read_ok) {
      result = carries_needle(c->args, alen, c->n1, c->n1len, c->n2, c->n2len)
                    ? TG_MEMBER : TG_NONMEMBER;
#ifdef IOMON_TG_FAULT_TEST
      if (result == TG_NONMEMBER && pid == iomon_tg_fault_exiting_pid)
        result = TG_DEAD;
#endif
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
          if (creator_class(c, j, depth + 1) == TG_NONMEMBER)
            result = TG_NONMEMBER;
        }
      }
      if (result == TG_UNREADABLE && creator_predates_root(c, idx))
        result = TG_NONMEMBER;
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
int iomon_tg_sweep(int32_t self, uint64_t root_start_abs,
                    uint64_t root_uniqueid, const char *n1,
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
  c.root_uniqueid = root_uniqueid;
  {
    uint64_t self_puniq = 0;
    if (!iomon_tg_unique_ids(self, &c.self_uniqueid, &self_puniq))
      c.self_uniqueid = 0;
  }
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
