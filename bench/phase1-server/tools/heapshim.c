// heapshim.c: LD_PRELOAD malloc interposer for glibc. It keeps, per call stack, the live
// bytes and the bytes allocated since the start, and writes them with /proc/self/maps to
// $HEAPSHIM_OUT when the file $HEAPSHIM_OUT.trigger appears (the trigger is removed after
// the dump). Every 5 s it appends the totals to $HEAPSHIM_OUT.stats. heapsym.py turns a
// dump into a report.
//
// A measurement aid, not production code: one global lock, a backtrace per allocation (the
// process runs many times slower), fixed-size tables, and a realloc counts as a new
// allocation of the new size. Sizes are the requested sizes, not the allocator's chunks.
//
// Build: gcc -O2 -shared -fPIC -o heapshim.so heapshim.c -ldl -lpthread
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define DEPTH 28
#define SKIP 1
#define NSTACK (1u << 22)
#define NPTR (1u << 24)

typedef struct { uint64_t hash; long live; long count; long cum; long calls; int depth; void *pc[DEPTH]; } stack_t_;
typedef struct { void *p; size_t size; uint32_t sid; } ptr_t;

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static int (*real_posix_memalign)(void **, size_t, size_t);
static void *(*real_aligned_alloc)(size_t, size_t);
static void *(*real_memalign)(size_t, size_t);

static stack_t_ *stacks;
static ptr_t *ptrs;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static __thread int in_hook;
static int ready;
static long n_calls, n_frees, live_total, peak_total;
static char boot[1 << 16];
static size_t boot_used;

static void *boot_alloc(size_t n) {
  n = (n + 15) & ~15ul;
  if (boot_used + n > sizeof boot) return NULL;
  void *p = boot + boot_used; boot_used += n; return p;
}
static int is_boot(void *p) { return (char *)p >= boot && (char *)p < boot + sizeof boot; }

static uint32_t stack_id(void **pc, int n) {
  n -= SKIP; if (n < 0) n = 0;
  uint64_t h = 1469598103934665603ull;
  for (int i = 0; i < n; i++) { h ^= (uint64_t)pc[i + SKIP]; h *= 1099511628211ull; }
  uint32_t i = (uint32_t)(h % NSTACK);
  for (uint32_t probe = 0;; probe++) {
    if (probe > 4096) return 0;   // table crowded: account to bucket 0
    if (stacks[i].hash == h) return i;
    if (stacks[i].hash == 0) {
      stacks[i].hash = h; stacks[i].depth = n;
      memcpy(stacks[i].pc, pc + SKIP, n * sizeof(void *));
      return i;
    }
    i = (i + 1) % NSTACK;
  }
}
static uint32_t ptr_slot(void *p) {
  uint64_t x = (uint64_t)(uintptr_t)p; x ^= x >> 33; x *= 0xff51afd7ed558ccdull; x ^= x >> 33;
  return (uint32_t)(x & (NPTR - 1));
}

static void record(void *p, size_t size) {
  if (!p || !ready || in_hook) return;
  in_hook = 1;
  void *pc[DEPTH + SKIP];
  int n = backtrace(pc, DEPTH + SKIP);   // outside the lock: the unwinder takes the loader lock
  pthread_mutex_lock(&mu);
  uint32_t sid = stack_id(pc, n);
  stacks[sid].live += size; stacks[sid].count++; stacks[sid].cum += size; stacks[sid].calls++;
  n_calls++; live_total += size; if (live_total > peak_total) peak_total = live_total;
  uint32_t i = ptr_slot(p);
  while (ptrs[i].p) i = (i + 1) % NPTR;
  ptrs[i].p = p; ptrs[i].size = size; ptrs[i].sid = sid;
  pthread_mutex_unlock(&mu);
  in_hook = 0;
}
static void forget(void *p) {
  if (!p || !ready || in_hook) return;
  pthread_mutex_lock(&mu);
  uint32_t i = ptr_slot(p);
  for (uint32_t k = 0; k < NPTR && ptrs[i].p; k++, i = (i + 1) % NPTR) {
    if (ptrs[i].p == p) {
      stacks[ptrs[i].sid].live -= ptrs[i].size; stacks[ptrs[i].sid].count--; live_total -= ptrs[i].size; n_frees++;
      // Backward-shift deletion keeps the probe chains short (no tombstones).
      uint32_t j = i;
      for (;;) {
        j = (j + 1) % NPTR;
        if (!ptrs[j].p) break;
        uint32_t h = ptr_slot(ptrs[j].p);
        int move = (i <= j) ? (h <= i || h > j) : (h <= i && h > j);
        if (move) { ptrs[i] = ptrs[j]; i = j; }
      }
      ptrs[i].p = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&mu);
}

static void dump(const char *path) {
  int fd = open(path ? path : "/tmp/heapshim.out", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return;
  pthread_mutex_lock(&mu);
  char buf[512];
  // Copy /proc/self/maps first so the offline symboliser knows the load base.
  int m = open("/proc/self/maps", O_RDONLY); ssize_t r;
  dprintf(fd, "MAPS\n");
  while ((r = read(m, buf, sizeof buf)) > 0)
    if (write(fd, buf, r) != r) break;
  close(m);
  dprintf(fd, "TOTALS calls=%ld frees=%ld live=%ld peak=%ld\n", n_calls, n_frees, live_total, peak_total);
  dprintf(fd, "STACKS\n");
  for (uint32_t i = 0; i < NSTACK; i++) {
    if (stacks[i].hash && (stacks[i].live > 0 || stacks[i].cum > (1 << 20))) {
      dprintf(fd, "S %ld %ld %ld %ld", stacks[i].live, stacks[i].count, stacks[i].cum, stacks[i].calls);
      for (int k = 0; k < stacks[i].depth; k++) dprintf(fd, " %p", stacks[i].pc[k]);
      dprintf(fd, "\n");
    }
  }
  pthread_mutex_unlock(&mu);
  close(fd);
}

// Dumps when <HEAPSHIM_OUT>.trigger appears (a thread, not a signal handler: the handler
// could interrupt a thread that holds the table lock).
static void *watcher(void *arg) {
  (void)arg;
  in_hook = 1;
  const char *out = getenv("HEAPSHIM_OUT");
  if (!out) out = "/tmp/heapshim.out";
  char trig[4096]; snprintf(trig, sizeof trig, "%s.trigger", out);
  for (;;) {
    if (access(trig, F_OK) == 0) { dump(out); unlink(trig); }
    static int tick; if (++tick % 25 == 0) {
      char st[4200]; snprintf(st, sizeof st, "%s.stats", out);
      FILE *f = fopen(st, "a"); if (f) { fprintf(f, "calls=%ld frees=%ld live=%ld peak=%ld\n", n_calls, n_frees, live_total, peak_total); fclose(f); }
    }
    usleep(200000);
  }
  return NULL;
}

__attribute__((constructor)) static void init(void) {
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_free = dlsym(RTLD_NEXT, "free");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  real_memalign = dlsym(RTLD_NEXT, "memalign");
  stacks = mmap(NULL, sizeof(stack_t_) * NSTACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  ptrs = mmap(NULL, sizeof(ptr_t) * NPTR, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  in_hook = 1; void *pc[4]; backtrace(pc, 4); in_hook = 0;   // load the unwinder now
  ready = 1;
  pthread_t t; pthread_create(&t, NULL, watcher, NULL);
}

void *malloc(size_t n) {
  if (!real_malloc) return boot_alloc(n);
  void *p = real_malloc(n); record(p, n); return p;
}
void *calloc(size_t a, size_t b) {
  if (!real_calloc) { void *p = boot_alloc(a * b); if (p) memset(p, 0, a * b); return p; }
  void *p = real_calloc(a, b); record(p, a * b); return p;
}
void free(void *p) {
  if (!p || is_boot(p)) return;
  forget(p); real_free(p);
}
void *realloc(void *p, size_t n) {
  if (is_boot(p)) { void *q = malloc(n); if (q) memcpy(q, p, n); return q; }
  forget(p); void *q = real_realloc(p, n); record(q, n); return q;
}
int posix_memalign(void **out, size_t al, size_t n) {
  int rc = real_posix_memalign(out, al, n); if (rc == 0) record(*out, n); return rc;
}
void *aligned_alloc(size_t al, size_t n) { void *p = real_aligned_alloc(al, n); record(p, n); return p; }
void *memalign(size_t al, size_t n) { void *p = real_memalign(al, n); record(p, n); return p; }
