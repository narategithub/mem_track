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

static void *(*libc_malloc)(size_t sz) = NULL;
static void (*libc_free)(void *p) = NULL;
static void *(*libc_calloc)(size_t n, size_t sz) = NULL;
static void *(*libc_realloc)(void *p, size_t sz) = NULL;

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

void *malloc(size_t sz)
{
	/*
	 * Add extra 8 bytes to the request sz for mem_track reference.
	 */
	size_t idx, start;
	mem_t m = libc_malloc(sz + sizeof(*m));
	if (!m)
		return NULL;
	WRITE("DEBUG malloc ");
	WRITE_CALLER(0);
	WRITE("\n");
	/* allocate track entry */
	start = idx = ((uint64_t)m->ptr) % track_len;
	while (0 == __sync_bool_compare_and_swap(&track_array[idx].ptr, 0, m->ptr)) {
		idx = (idx+1)%track_len;
		assert( idx != start ); /* otherwise, ENOMEM */
	}
	Dl_info _inf;
	dladdr(RETURN_ADDR(0), &_inf);
	m->sig = SIGNATURE;
	m->track = &track_array[idx];
	m->track->sz = sz;
	m->track->caller = _inf.dli_saddr;
	return m->ptr;
}

void *calloc(size_t n, size_t sz)
{
	WRITE("DEBUG calloc\n");
	return libc_calloc(n, sz);
}

void *realloc(void *p, size_t sz)
{
	WRITE("DEBUG realloc\n");
	return  libc_realloc(p, sz);
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
	libc_free(m);
}

static void __attribute__((constructor)) __init__()
{
	int rc;
	uint64_t i;
	const char *path = ENV_STR(MEM_TRACK_FILE);
	track_len = ENV_U64(MEM_TRACK_LEN);
	assert(track_len > 0);
	size_t map_sz = track_len*sizeof(struct mem_track_entry);

	track_fd = open(path, O_CREAT|O_RDWR, 0644);
	assert(track_fd >= 0);
	rc = ftruncate(track_fd, 0);
	assert(rc >= 0);
	rc = ftruncate(track_fd, map_sz);
	assert(rc >= 0);

	track_array = mmap(NULL, map_sz, PROT_READ|PROT_WRITE, MAP_SHARED, track_fd, 0);
	assert(track_array != MAP_FAILED);
	for (i = 0; i < track_len; i++) {
		assert(track_array[i].ptr == 0);
		assert(track_array[i].caller == 0);
	}
	libc_malloc = dlsym(RTLD_NEXT, "malloc");
	libc_calloc = dlsym(RTLD_NEXT, "calloc");
	libc_realloc = dlsym(RTLD_NEXT, "realloc");
	libc_free = dlsym(RTLD_NEXT, "free");
}
