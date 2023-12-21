#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef DEBUG_ALL_CALLS
#include <alloca.h>
#endif
#if defined(DEBUG_CHUNKS) || defined(DEBUG_ALL_CALLS)
#include <stdio.h>
#endif

// Options for compiling:
//  - CHECK_CHUNK_HEADER_MAPPING: Add expensive sanity checks (is the chunk header mapped) for realloc and malloc_usable_size
//                                This is probably unnecessary unless you feed an unsound pointer into realloc.
//  - DEBUG_ALL_CALLS: Log every call to a function in this library
//  - DEBUG_CHUNKS: Log every allocated safe-mode chunk
//  - DEBUG_SIGNAL: Set this to a signal number to enable safe mode when this signal is encountered
//  - NDEBUG: Remove mmap sanity checks for faster allocations
//  - NEVER_LEAVE_SAFE_MODE: Error when we would fall back to libc malloc_usable_size after entering safe mode
//  - NO_STARTUP_FALLBACK_ALLOCATOR: Remove the fallback allocator for dlsym for a slight reduction in overhead

#ifndef NO_STARTUP_FALLBACK_ALLOCATOR
// Can't be thread_local, but it also doesn't matter since there is only one loader thread
static bool in_setup = true;
static bool in_dlsym_allocator = false;
#endif

static atomic_bool safe_mode = false;
void allocator_switch_to_safe_mode(void)
{
    atomic_store_explicit(&safe_mode, true, memory_order_release);
}

#ifdef DEBUG_SIGNAL
static void debug_handler(int signal)
{
    (void) signal;
    allocator_switch_to_safe_mode();
}
__attribute__((constructor)) static inline void set_up_debug_handler(void)
{
    signal(DEBUG_SIGNAL, debug_handler);
}
#endif

#define PAGE_SIZE 0x1000ul
#define PAGE_CEIL(size) ((size) & (PAGE_SIZE - 1) ? ((size) | (PAGE_SIZE - 1)) + 1 : (size))

#define CHUNK_MAGIC 0xf45afe5afe5afef4ul
struct chunk_header {
    uintptr_t magic;
    size_t size;
};

__attribute__((noreturn)) static inline void fatal_error(const char *message)
{
    long pid;
    __asm__ volatile ( "syscall" :: "a"(SYS_write), "D"(STDERR_FILENO), "S"(message), "d"(__builtin_strlen(message)) : "rcx", "r11" );
    __asm__ volatile ( "syscall" : "=a"(pid) : "a"(SYS_getpid) : "rcx", "r11" );
    __asm__ volatile ( "syscall" :: "a"(SYS_kill), "D"(pid), "S"(SIGABRT) : "rcx", "r11" );
    __builtin_trap();
}

__attribute__((always_inline)) static inline void *raw_mmap(size_t size, size_t alignment)
{
#define __raw_mmap_asm() \
    do { \
        __asm__ volatile ( \
            "syscall" \
            : "=a"(mapping) \
            : "a"(SYS_mmap), "D"(NULL), "S"(size), "d"(PROT_READ | PROT_WRITE), "r"(flags), "r"(fd), "r"(offset) \
            : "rcx", "r11" \
        ); \
        if (__builtin_expect((uintptr_t) mapping > (uintptr_t) -0x1000, 0)) \
            return NULL; \
    } while (0)

    register size_t flags __asm__("r10") = MAP_PRIVATE | MAP_ANONYMOUS;
    register int fd __asm__("r8") = -1;
    register off_t offset __asm__("r9") = 0;

    // Here's a really ugly hack that allows us to store metadata ahead of everything else and keep alignment otherwise.
    size += sizeof(struct chunk_header);

    void *mapping;
    void *result;
    if (__builtin_expect(alignment > sizeof(struct chunk_header), 0)) {
        size += alignment;
        size = PAGE_CEIL(size);
        __raw_mmap_asm();
        uintptr_t last_possible = (uintptr_t) mapping + size - alignment;
        result = (void *) (last_possible - (last_possible & (alignment - 1)));
    } else {
        size = PAGE_CEIL(size);
        __raw_mmap_asm();
        result = (void *) ((uintptr_t) mapping + sizeof(struct chunk_header));
    }

    struct chunk_header *hdr = (struct chunk_header *) ((uintptr_t) result - sizeof(struct chunk_header));
    if (__builtin_expect((uintptr_t) mapping > (uintptr_t) result - sizeof(struct chunk_header), 0))
        fatal_error("While allocating aligned storage: not enough space for chunk header\n");
    hdr->magic = CHUNK_MAGIC;
    hdr->size = (uintptr_t) mapping + size - (uintptr_t) result;

#ifdef DEBUG_CHUNKS
    char static_buffer[128];
    int length = snprintf(static_buffer, sizeof(static_buffer), "Allocated %ld bytes at %p\n", hdr->size, result);
    int rc, c = 0; \
    do {rc = write(STDOUT_FILENO, static_buffer, length); } while (rc == -1 && c++ <= 1); \
#endif

    return result;
#undef __raw_mmap_asm
}

// Tracking for realloc and malloc_usable_size.
static inline bool is_safe_alloc_chunk(struct chunk_header *hdr)
{
#ifndef ASSUME_SAFE_MAPPING_SIZE
    long result;
    uintptr_t hdr_page = (uintptr_t) hdr & ~PAGE_SIZE;
    unsigned char hdr_mincore = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(SYS_mincore), "D"(hdr_page), "S"(PAGE_SIZE), "d"(&hdr_mincore)
        : "rcx", "r11"
    );
    if (result == -ENOMEM)
        return false;
#endif
    return hdr->magic == CHUNK_MAGIC;
}

static inline size_t get_mapping_size(void *ptr);

static inline void *resolve_next(const char *name)
{
#ifndef NO_STARTUP_FALLBACK_ALLOCATOR
    in_dlsym_allocator = true;
#endif
    void *symbol = dlsym(RTLD_NEXT, name);
    if (symbol == NULL)
        __asm__ volatile ("ud2");
#ifndef NO_STARTUP_FALLBACK_ALLOCATOR
    in_dlsym_allocator = false;
    in_setup = false;
#endif
    return symbol;
}

#define __raw_is_safe_mode() atomic_load_explicit(&safe_mode, memory_order_acquire)
#ifdef NO_STARTUP_FALLBACK_ALLOCATOR
#define IS_SAFE_MODE() __builtin_expect(__raw_is_safe_mode(), 0)
#else
#define IS_SAFE_MODE() __builtin_expect(__raw_is_safe_mode() || in_dlsym_allocator, 0)
#endif

#define CONCAT(a, b) a##b
#define STRINGIFY(a) #a
#define GENERATE_IFUNC(return_type, for_name, ...) \
    __attribute__((used)) static inline return_type (*CONCAT(resolve_, for_name)(void))(__VA_ARGS__); \
    __attribute__((ifunc("resolve_" STRINGIFY(for_name)))) static inline return_type for_name(__VA_ARGS__); \
    __attribute__((used)) static inline return_type (*CONCAT(resolve_, for_name)(void))(__VA_ARGS__)

#define GENERATE(return_type, for_name, ...) \
    return_type for_name(__VA_ARGS__); \
    GENERATE_IFUNC(return_type, CONCAT(unsafe_, for_name), ##__VA_ARGS__) { \
        return (return_type (*) (__VA_ARGS__)) resolve_next(STRINGIFY(for_name)); \
    }

GENERATE(void *, malloc,             size_t size);
GENERATE(void,   free,               void *ptr);
GENERATE(void *, calloc,             size_t nmemb,     size_t size);
GENERATE(void *, realloc,            void *ptr,        size_t size);
GENERATE(void *, aligned_alloc,      size_t alignment, size_t size);
GENERATE(int,    posix_memalign,     void **memptr,    size_t alignment, size_t size);
GENERATE(void *, memalign,           size_t alignment, size_t size);
GENERATE(void *, pvalloc,            size_t size);
GENERATE(void *, valloc,             size_t size);
GENERATE(size_t, malloc_usable_size, void *ptr);

#ifdef DEBUG_ALL_CALLS
static bool in_log = false;
#define __raw_write(fd, literal) __asm__ volatile ( "syscall" :: "a"(SYS_write), "D"(STDERR_FILENO), "S"(literal), "d"(sizeof(literal) - 1) : "rcx", "r11" )
#define LOG(name, argfmt, ...) \
    do { \
        if (in_dlsym_allocator) \
            __raw_write(STDERR_FILENO, "[dlsym] " name "\n"); \
        else if (in_setup) \
            __raw_write(STDERR_FILENO, "[setup] " name "\n"); \
        else if (in_log) \
            __raw_write(STDERR_FILENO, "[logging] " name "\n"); \
        else { \
            /* dprintf does an internal malloc which we want to avoid... */ \
            in_log = true; \
            int __log_size = snprintf(NULL, 0, "%s" name argfmt "\n", IS_SAFE_MODE() ? "[safe] " : "", ##__VA_ARGS__); \
            char *__log_buffer = alloca(__log_size + 1); \
            snprintf(__log_buffer, __log_size + 1, "%s" name argfmt "\n", IS_SAFE_MODE() ? "[safe] " : "", ##__VA_ARGS__); \
            int rc, c = 0; \
            do {rc = write(STDERR_FILENO, __log_buffer, __log_size); } while (rc == -1 && c++ <= 1); \
            in_log = false; \
        } \
    } while (0)
#else
#define LOG(fmt, ...) do {} while (0)
#endif

void *malloc(size_t size)
{
    LOG("malloc", "(size = %#lx)", size);
    if (IS_SAFE_MODE())
        return raw_mmap(size, 0);
    else
        return unsafe_malloc(size);
}

void free(void *ptr)
{
    LOG("free", "(ptr = %p)", ptr);
    if (!IS_SAFE_MODE())
        unsafe_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    LOG("calloc", "(nmemb = %#lx, size = %#lx)", nmemb, size);
    if (IS_SAFE_MODE()) {
        size_t actual;
        if (__builtin_umull_overflow(nmemb, size, &actual))
            return NULL;
        return raw_mmap(actual, 0);
    } else {
        return unsafe_calloc(nmemb, size);
    }
}

void *realloc(void *ptr, size_t size)
{
    LOG("realloc", "(ptr = %p, size = %#lx)", ptr, size);
    if (IS_SAFE_MODE()) {
        size_t old_size = malloc_usable_size(ptr);
        if (old_size >= size)
            return ptr;
        void *allocated = raw_mmap(size, 0);
        if (allocated && ptr)
            __builtin_memcpy(allocated, ptr, old_size);
        return allocated;
    } else {
        return unsafe_realloc(ptr, size);
    }
}

void *aligned_alloc(size_t alignment, size_t size)
{
    LOG("aligned_alloc", "(alignment = %#lx, size = %#lx)", alignment, size);
    if (IS_SAFE_MODE())
        return raw_mmap(size, alignment);
    else
        return unsafe_aligned_alloc(alignment, size);
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    LOG("posix_memalign", "(memptr = %p, alignment = %#lx, size = %#lx)", (void *) memptr, alignment, size);
    if (IS_SAFE_MODE()) {
        void *allocated = raw_mmap(size, alignment);
        if (allocated) {
            *memptr = allocated;
            return 0;
        }
        return ENOMEM;
    } else {
        return unsafe_posix_memalign(memptr, alignment, size);
    }
}

void *memalign(size_t alignment, size_t size)
{
    LOG("memalign", "(alignment = %#lx, size = %#lx)", alignment, size);
    if (IS_SAFE_MODE())
        return raw_mmap(size, alignment);
    else
        return unsafe_memalign(alignment, size);
}

void *pvalloc(size_t size)
{
    LOG("pvalloc", "(size = %#lx)", size);
    if (IS_SAFE_MODE())
        return raw_mmap(PAGE_CEIL(size), PAGE_SIZE);
    else
        return unsafe_pvalloc(size);
}

void *valloc(size_t size)
{
    LOG("valloc", "(size = %#lx)", size);
    if (IS_SAFE_MODE())
        return raw_mmap(size, PAGE_SIZE);
    else
        return unsafe_valloc(size);
}

size_t malloc_usable_size(void *ptr)
{
    LOG("malloc_usable_size", "(ptr = %p)", ptr);
    if (IS_SAFE_MODE())
        return get_mapping_size(ptr);
    else
        return unsafe_malloc_usable_size(ptr);
}


static inline size_t get_mapping_size(void *ptr)
{
    // This isn't guaranteed to have been allocated by us, or to even exist if this is a libc allocation
    struct chunk_header *hdr = (struct chunk_header *) ((uintptr_t) ptr - sizeof(struct chunk_header));

    if (is_safe_alloc_chunk(hdr))
        return hdr->size;

#ifndef NEVER_LEAVE_SAFE_MODE
    return unsafe_malloc_usable_size(ptr); // If memory corruption is too severe, this will probably break.
#else
    fatal_error("Attempting to obtain mapping size of unknown (non-safe-mode) pointer, but NEVER_LEAVE_SAFE_MODE is enabled\n");
#endif
}
