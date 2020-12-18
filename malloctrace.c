/*
 * This is meant to be used with LD_PRELOAD.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEM_TRACK_FILE "mem.track"
#define MEM_TRACK_LEN 536870909 /* a prime near 512*1024*1024 */

#define SIGNATURE 0xACED12345678L

#define ENV_STR(X) ({ \
		char *e = getenv(#X); \
		e?e:(X); \
	})

#define ENV_U64(X) ({ \
		char *e = getenv(#X); \
		e?strtoul(e, NULL, 0):(X); \
	})

extern void *__libc_malloc(size_t sz);
extern void *__libc_calloc(size_t n, size_t sz);
extern void *__libc_realloc(void *p, size_t sz);
extern void __libc_free(void *p);

static void __init_once();

typedef struct mem_track_entry {
	void *ptr; /* ptr returned to the application. */
	size_t sz; /* requested size */
	void *caller; /* the caller */
} *mem_track_entry_t;

typedef struct mem {
	uint64_t sig; /* signature */
	mem_track_entry_t track;
	char ptr[]; /* ptr returned to the application */
} *mem_t;

static int track_fd = -1;
static mem_track_entry_t track_array = NULL;
uint64_t track_len = 0;

#define RETURN_ADDR(N) __builtin_extract_return_addr(__builtin_return_address(N))

#ifdef VERBOSE
#define WRITE(txt) write(1, txt, strlen(txt))
#define WRITE_CALLER(N) do { \
		void *_P = RETURN_ADDR(N); \
		Dl_info _inf; \
		dladdr(_P, &_inf); \
		if (!_inf.dli_sname) { \
			WRITE("main"); \
			WRITE(" "); \
			WRITE_HEX(_inf.dli_saddr); \
			WRITE(" "); \
		} else { \
			WRITE(_inf.dli_sname); \
			WRITE(" "); \
			WRITE_HEX(_inf.dli_saddr); \
			WRITE(" "); \
		} \
	} while(0)
#define WRITE_FRAME(N) do { \
		char _A[17]; \
		void *_P = __builtin_frame_address(N); \
		u64_hex((uint64_t)_P, _A); \
		WRITE("FRAME: "); \
		WRITE(_A); \
} while(0)
#define WRITE_HEX(X) do { \
		char _A[17]; \
		u64_hex((uint64_t)X, _A); \
		WRITE(_A); \
} while (0)
#else
#define WRITE(txt)      /*  no-op  */
#define WRITE_CALLER(N) /*  no-op  */
#define WRITE_FRAME(N)  /*  no-op  */
#define WRITE_HEX(X)    /*  no-op  */
#endif

const char *_hex = "0123456789abcdef";

void u64_hex(uint64_t x, char *hex)
{
	int i;
	uint64_t mask = 0xf;
	hex[16] = '\0';
	for (i = 15; i >= 0; i--) {
		hex[i] = _hex[ mask & x ];
		x >>= 4;
	}
}

mem_track_entry_t track_alloc(void *ptr)
{
	size_t idx, start;
	start = idx = ((uint64_t)ptr) % track_len;
	while (0 == __sync_bool_compare_and_swap(&track_array[idx].ptr, 0, ptr)) {
		idx = (idx+1)%track_len;
		assert( idx != start ); /* otherwise, ENOMEM */
	}
	return &track_array[idx];
}

void track_release(mem_track_entry_t ent)
{
	ent->caller = NULL;
	ent->sz = 0;
	ent->ptr = NULL;
}

void *malloc(size_t sz)
{
	__init_once();
	mem_t m = __libc_malloc(sz + sizeof(*m));
	if (!m)
		return NULL;
	WRITE("DEBUG malloc ");
	WRITE_CALLER(0);
	WRITE("\n");
	/* allocate track entry */
	Dl_info _inf;
	dladdr(RETURN_ADDR(0), &_inf);
	m->sig = SIGNATURE;
	m->track = track_alloc(m->ptr); /* already set track->ptr */
	m->track->sz = sz;
	m->track->caller = _inf.dli_saddr;
	return m->ptr;
}

void *calloc(size_t n, size_t sz)
{
	__init_once();
	mem_t m = __libc_calloc(1, n*sz + sizeof(*m));
	if (!m)
		return NULL;
	WRITE("DEBUG calloc ");
	WRITE_CALLER(0);
	WRITE("\n");
	/* allocate track entry */
	Dl_info _inf;
	dladdr(RETURN_ADDR(0), &_inf);
	m->sig = SIGNATURE;
	m->track = track_alloc(m->ptr); /* already set track->ptr */
	m->track->sz = sz;
	m->track->caller = _inf.dli_saddr;
	return m->ptr;
}

void *realloc(void *p, size_t sz)
{
	__init_once();
	if (!p) {
		/* this is just mlloc */
		mem_t m = __libc_malloc(sz + sizeof(*m));
		if (!m)
			return NULL;
		WRITE("DEBUG realloc ");
		WRITE_CALLER(0);
		WRITE("\n");
		/* allocate track entry */
		Dl_info _inf;
		dladdr(RETURN_ADDR(0), &_inf);
		m->sig = SIGNATURE;
		m->track = track_alloc(m->ptr); /* already set track->ptr */
		m->track->sz = sz;
		m->track->caller = _inf.dli_saddr;
		return m->ptr;
	}

	mem_t m = p - sizeof(*m);
	mem_t new_m = __libc_realloc(m, sz + sizeof(*m));
	if (new_m != m) {
		track_release(new_m->track);
		new_m->track = track_alloc(new_m->ptr);
	}
	Dl_info _inf;
	dladdr(RETURN_ADDR(0), &_inf);
	new_m->track->sz = sz;
	new_m->track->caller = _inf.dli_saddr;

	return  new_m->ptr;
}

void free(void *p)
{
	if (!p)
		return;
	mem_t m = p - sizeof(*m);
	char addr[17];
	u64_hex((uint64_t)p, addr);
	WRITE("DEBUG free: ");
	WRITE(addr);
	WRITE(" ");
	WRITE_CALLER(0);
	WRITE("\n");
	assert(m->sig == SIGNATURE);
	assert(m->track->ptr == m->ptr);
	/* releasing track */
	m->track->caller = 0;
	m->track->sz = 0;
	m->track->ptr = 0;
	/* free */
	__libc_free(m);
}

pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
const char *dec = "0123456789";

void int_str(int x, char *buff)
{
	int m = 1000000000;
	int i;
	/* get rid of leading zeros */
	while (0 == (x/m)) {
		m /= 10;
	}
	i = 0;
	while (m) {
		buff[i] = dec[x/m];
		i++;
		x %= m;
		m /= 10;
	}
	buff[i] = 0;
}

static void __init_once()
{
	static int initialized = 0;
	if (initialized)
		return;
	pthread_mutex_lock(&init_mutex);
	if (initialized)
		goto out; /* initialized by the other thread */
	int rc;
	pid_t pid = getpid();
	char _pid[64];
	char _path[PATH_MAX];
	const char *path = ENV_STR(MEM_TRACK_FILE);

	/* global track_len */
	track_len = ENV_U64(MEM_TRACK_LEN);
	assert(track_len > 0);

	size_t map_sz = track_len*sizeof(struct mem_track_entry);

	/* build path */
	strcpy(_path, path);
	strcat(_path, ".");
	int_str(pid, _pid);
	strcat(_path, _pid);

	track_fd = open(_path, O_CREAT|O_RDWR|O_CLOEXEC, 0644);
	assert(track_fd >= 0);
	rc = ftruncate(track_fd, 0);
	assert(rc >= 0);
	rc = ftruncate(track_fd, map_sz);
	assert(rc >= 0);

	track_array = mmap(NULL, map_sz, PROT_READ|PROT_WRITE, MAP_SHARED, track_fd, 0);
	assert(track_array != MAP_FAILED);
	#if 0
	for (i = 0; i < track_len; i++) {
		assert(track_array[i].ptr == 0);
		assert(track_array[i].caller == 0);
	}
	#endif
	initialized = 1;
 out:
	pthread_mutex_unlock(&init_mutex);
}

static void __attribute__((constructor)) __init__()
{
	__init_once();
}
