// trimshim.c: LD_PRELOAD helper that calls malloc_trim(0) every 10 s from its own thread,
// to measure what returning freed heap pages to the kernel would give. Scratch tool.
// Build: gcc -O2 -shared -fPIC -o trimshim.so trimshim.c -lpthread
#define _GNU_SOURCE
#include <malloc.h>
#include <pthread.h>
#include <unistd.h>
static void *loop(void *arg) { (void)arg; for (;;) { sleep(10); malloc_trim(0); } return 0; }
__attribute__((constructor)) static void init(void) { pthread_t t; pthread_create(&t, 0, loop, 0); pthread_detach(t); }
