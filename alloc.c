// Teaching Allocator Demo: malloc→brk→(virtual memory map)→write
// --------------------------------------------------------------
// This program is a teaching tool showing how malloc requests memory from
// the OS via sbrk or mmap, how the heap grows, and how writes happen to
// those pages. It prints verbose logs for each step.
//
// Build:   make (see provided Makefile)
// Run:     ./alloc
//
// While running, you can inspect memory mappings:
//   cat /proc/$(pidof alloc)/maps | grep -E '\[heap\]|\s00:00\s0'

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define ALIGN16(x) (((x) + 15u) & ~15u)
#define MAX(a,b) ((a)>(b)?(a):(b))

static void *heap_base_at_start;

static void print_brk(const char *tag) {
    void *brk_now = sbrk(0);
    printf("[SBRK] %-12s brk=%p (heap size so far: %zd bytes)\n",
           tag, brk_now, (ssize_t)((char*)brk_now - (char*)heap_base_at_start));
}

static void show_maps(void) {
    printf("[MAPS] --- /proc/self/maps (key anonymous + heap lines) ---\n");
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("fopen /proc/self/maps"); return; }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "[heap]")) { fputs(line, stdout); continue; }
        if (strstr(line, " 00:00 0") && !strchr(line, '/')) {
            fputs(line, stdout);
        }
    }
    fclose(f);
    printf("[MAPS] ------------------------------------------------\n");
}

typedef struct block {
    size_t size;
    bool   free;
    struct block *next;
} block_t;

static block_t *free_list = NULL;
static size_t header_size(void) { return ALIGN16(sizeof(block_t)); }

static block_t *split_block(block_t *b, size_t want) {
    size_t hsz = header_size();
    if (b->size >= want + hsz + 16) {
        char *base = (char*)(b + 1);
        block_t *nb = (block_t*)(base + want);
        nb->size = b->size - want - hsz;
        nb->free = true;
        nb->next = b->next;
        b->size = want;
        b->next = nb;
        printf("[SPLIT] block %p -> used %zu, new free %p (%zu)\n", (void*)b, b->size, (void*)nb, nb->size);
    }
    return b;
}

static block_t *request_from_os(size_t need_bytes) {
    size_t hsz = header_size();
    size_t total = ALIGN16(need_bytes + hsz);
    size_t pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t ask = pages * PAGE_SIZE;
    void *old_brk = sbrk(0);
    void *res = sbrk(ask);
    if (res == (void*)-1) { perror("sbrk"); return NULL; }
    printf("[OS]    sbrk  asked=%zu (≈%zu pages) old_brk=%p new_brk=%p\n",
           ask, ask / PAGE_SIZE, old_brk, sbrk(0));
    block_t *b = (block_t*)res;
    b->size = ask - hsz;
    b->free = true;
    b->next = NULL;
    if (!free_list) free_list = b; else {
        block_t *cur = free_list; while (cur->next) cur = cur->next; cur->next = b;
    }
    return b;
}

static block_t *find_block(size_t want) {
    for (block_t *cur = free_list; cur; cur = cur->next)
        if (cur->free && cur->size >= want) return cur;
    return NULL;
}

static void *mymalloc_small(size_t n) {
    size_t want = ALIGN16(n);
    printf("\n[MALLOC] small  request=%zu aligned=%zu\n", n, want);
    print_brk("before");
    block_t *b = find_block(want);
    if (!b) { printf("[ALLOC] no fit found → request from OS\n"); b = request_from_os(MAX(want, PAGE_SIZE)); if (!b) return NULL; }
    split_block(b, want);
    b->free = false;
    void *user = (void*)(b + 1);
    printf("[ALLOC] serve %zu bytes at %p (header=%p size=%zu)\n", want, user, (void*)b, b->size);
    print_brk("after");
    return user;
}

typedef struct bigmap {
    void *addr;
    size_t size;
    struct bigmap *next;
} bigmap_t;

static bigmap_t *bigmaps = NULL;

static void *mymalloc_large(size_t n) {
    size_t want = ALIGN16(n);
    printf("\n[MALLOC] LARGE  request=%zu aligned=%zu via mmap()\n", n, want);
    void *p = mmap(NULL, want, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return NULL; }
    bigmap_t *bm = (bigmap_t*)malloc(sizeof *bm);
    bm->addr = p; bm->size = want; bm->next = bigmaps; bigmaps = bm;
    printf("[MMAP ] got  %zu bytes at %p (own VM region)\n", want, p);
    return p;
}

static void myfree_large(void *p) {
    bigmap_t **pp = &bigmaps;
    while (*pp) {
        if ((*pp)->addr == p) {
            bigmap_t *dead = *pp;
            *pp = (*pp)->next;
            munmap(dead->addr, dead->size);
            printf("[MUNMAP] released %zu bytes at %p\n", dead->size, dead->addr);
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
    printf("[FREE ] large: pointer %p not found\n", p);
}

static void try_coalesce(void) {
    block_t *cur = free_list;
    while (cur && cur->next) {
        char *cur_end = (char*)(cur + 1) + cur->size;
        if (cur->free && cur->next->free && (char*)cur->next == cur_end) {
            printf("[COAL ] merge %p (%zu) + %p (%zu)\n", (void*)cur, cur->size, (void*)cur->next, cur->next->size);
            cur->size += header_size() + cur->next->size;
            cur->next = cur->next->next;
        } else cur = cur->next;
    }
}

static void myfree_small(void *p) {
    if (!p) return;
    block_t *b = ((block_t*)p) - 1;
    b->free = true;
    printf("\n[FREE ] small at %p (header %p size=%zu)\n", p, (void*)b, b->size);
    try_coalesce();
}

static const size_t LARGE_THRESHOLD = 1 << 20;

static void *teach_malloc(size_t n) {
    return (n >= LARGE_THRESHOLD) ? mymalloc_large(n) : mymalloc_small(n);
}

static void teach_free(void *p) {
    void *brk_now = sbrk(0);
    if (p > heap_base_at_start && p < brk_now) myfree_small(p); else myfree_large(p);
}

static void demo_write(void *p, size_t n, uint8_t val) {
    printf("[WRITE] set %zu bytes at %p to 0x%02x\n", n, p, val);
    memset(p, val, n);
    size_t show = n < 16 ? n : 16;
    printf("[READ ] first %zu bytes:", show);
    for (size_t i = 0; i < show; ++i) printf(" %02x", ((uint8_t*)p)[i]);
    printf("\n");
}

static unsigned get_pause_ms(void) {
    const char *s = getenv("TEACH_PAUSE_MS");
    if (!s || !*s) return 0;
    return (unsigned)strtoul(s, NULL, 10);
}
static void maybe_pause(void) {
    unsigned ms = get_pause_ms();
    if (ms) { fflush(stdout); usleep(ms * 1000); }
}

int main(void) {
    printf("\n=== Teaching Allocator Demo ===\n");
    printf("PID=%d  PAGE_SIZE=%d\n", getpid(), PAGE_SIZE);
    heap_base_at_start = sbrk(0);
    printf("[INIT ] program break start = %p\n", heap_base_at_start);
    show_maps(); maybe_pause();

    void *a = teach_malloc(2000);
    demo_write(a, 32, 0xAA); maybe_pause();

    void *b = teach_malloc(6000);
    demo_write(b, 32, 0xBB);
    show_maps(); maybe_pause();

    teach_free(a);
    void *c = teach_malloc(1000);
    demo_write(c, 16, 0xCC);
    show_maps(); maybe_pause();

    void *big = teach_malloc(2 * 1024 * 1024);
    demo_write(big, 64, 0xDD);
    show_maps(); maybe_pause();

    teach_free(b);
    teach_free(c);
    teach_free(big);
    show_maps(); maybe_pause();

    printf("\n[END  ] done. Inspect the logs above and /proc/self/maps output.\n");
    return 0;
}
