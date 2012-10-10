/*
 * Copyright (c) 2010, 2011, 2012 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * This allocator is based on the "The Slab Allocator: An Object-Caching
 * Kernel Memory Allocator" by Jeff Bonwick.
 *
 * It allows the allocation of objects (i.e. fixed-size typed buffers) from
 * caches and is efficient in both space and time. This implementation follows
 * many of the indications from the paper mentioned. The most notable
 * differences are outlined below.
 *
 * The per-cache self-scaling hash table for buffer-to-bufctl conversion,
 * described in 3.2.3 "Slab Layout for Large Objects", has been replaced by
 * a red-black tree storing slabs, sorted by address. The use of a
 * self-balancing tree for buffer-to-slab conversions provides a few advantages
 * over a hash table. Unlike a hash table, a BST provides a "lookup nearest"
 * operation, so obtaining the slab data (whether it is embedded in the slab or
 * off slab) from a buffer address simply consists of a "lookup nearest towards
 * 0" tree search. Storing slabs instead of buffers also considerably reduces
 * the number of elements to retain. Finally, a self-balancing tree is a true
 * self-scaling data structure, whereas a hash table requires periodic
 * maintenance and complete resizing, which is expensive. The only drawback is
 * that releasing a buffer to the slab layer takes logarithmic time instead of
 * constant time. But as the data set size is kept reasonable (because slabs
 * are stored instead of buffers) and because the CPU pool layer services most
 * requests, avoiding many accesses to the slab layer, it is considered an
 * acceptable tradeoff.
 *
 * This implementation uses per-cpu pools of objects, which service most
 * allocation requests. These pools act as caches (but are named differently
 * to avoid confusion with CPU caches) that reduce contention on multiprocessor
 * systems. When a pool is empty and cannot provide an object, it is filled by
 * transferring multiple objects from the slab layer. The symmetric case is
 * handled likewise.
 */

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <lib/assert.h>
#include <lib/limits.h>
#include <lib/list.h>
#include <lib/macros.h>
#include <lib/rbtree.h>
#include <lib/sprintf.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
#include <lib/string.h>
#include <machine/cpu.h>
#include <vm/vm_kmem.h>

/*
 * Minimum required alignment.
 */
#define KMEM_ALIGN_MIN 8

/*
 * Minimum number of buffers per slab.
 *
 * This value is ignored when the slab size exceeds a threshold.
 */
#define KMEM_MIN_BUFS_PER_SLAB 8

/*
 * Special slab size beyond which the minimum number of buffers per slab is
 * ignored when computing the slab size of a cache.
 */
#define KMEM_SLAB_SIZE_THRESHOLD (8 * PAGE_SIZE)

/*
 * Special buffer size under which slab data is unconditionnally allocated
 * from its associated slab.
 */
#define KMEM_BUF_SIZE_THRESHOLD (PAGE_SIZE / 8)

/*
 * The transfer size of a CPU pool is computed by dividing the pool size by
 * this value.
 */
#define KMEM_CPU_POOL_TRANSFER_RATIO 2

/*
 * Shift for the first general cache size.
 */
#define KMEM_CACHES_FIRST_SHIFT 5

/*
 * Number of caches backing general purpose allocations.
 */
#define KMEM_NR_MEM_CACHES 13

/*
 * Options for kmem_cache_alloc_verify().
 */
#define KMEM_AV_NOCONSTRUCT 0
#define KMEM_AV_CONSTRUCT   1

/*
 * Error codes for kmem_cache_error().
 */
#define KMEM_ERR_INVALID    0   /* Invalid address being freed */
#define KMEM_ERR_DOUBLEFREE 1   /* Freeing already free address */
#define KMEM_ERR_BUFTAG     2   /* Invalid buftag content */
#define KMEM_ERR_MODIFIED   3   /* Buffer modified while free */
#define KMEM_ERR_REDZONE    4   /* Redzone violation */

/*
 * Available CPU pool types.
 *
 * For each entry, the CPU pool size applies from the entry buf_size
 * (excluded) up to (and including) the buf_size of the preceding entry.
 *
 * See struct kmem_cpu_pool_type for a description of the values.
 */
static struct kmem_cpu_pool_type kmem_cpu_pool_types[] = {
    {  32768,   1, 0,           NULL },
    {   4096,   8, CPU_L1_SIZE, NULL },
    {    256,  64, CPU_L1_SIZE, NULL },
    {      0, 128, CPU_L1_SIZE, NULL }
};

/*
 * Caches where CPU pool arrays are allocated from.
 */
static struct kmem_cache kmem_cpu_array_caches[ARRAY_SIZE(kmem_cpu_pool_types)];

/*
 * Cache for off slab data.
 */
static struct kmem_cache kmem_slab_cache;

/*
 * General caches array.
 */
static struct kmem_cache kmem_caches[KMEM_NR_MEM_CACHES];

/*
 * List of all caches managed by the allocator.
 */
static struct list kmem_cache_list;
/* static struct mutex kmem_cache_list_mutex; */

static void kmem_cache_error(struct kmem_cache *cache, void *buf, int error,
                             void *arg);
static void * kmem_cache_alloc_from_slab(struct kmem_cache *cache);
static void kmem_cache_free_to_slab(struct kmem_cache *cache, void *buf);

static void *
kmem_buf_verify_bytes(void *buf, void *pattern, size_t size)
{
    char *ptr, *pattern_ptr, *end;

    end = buf + size;

    for (ptr = buf, pattern_ptr = pattern; ptr < end; ptr++, pattern_ptr++)
        if (*ptr != *pattern_ptr)
            return ptr;

    return NULL;
}

static void
kmem_buf_fill(void *buf, uint64_t pattern, size_t size)
{
    uint64_t *ptr, *end;

    assert(P2ALIGNED((unsigned long)buf, sizeof(uint64_t)));
    assert(P2ALIGNED(size, sizeof(uint64_t)));

    end = buf + size;

    for (ptr = buf; ptr < end; ptr++)
        *ptr = pattern;
}

static void *
kmem_buf_verify_fill(void *buf, uint64_t old, uint64_t new, size_t size)
{
    uint64_t *ptr, *end;

    assert(P2ALIGNED((unsigned long)buf, sizeof(uint64_t)));
    assert(P2ALIGNED(size, sizeof(uint64_t)));

    end = buf + size;

    for (ptr = buf; ptr < end; ptr++) {
        if (*ptr != old)
            return kmem_buf_verify_bytes(ptr, &old, sizeof(old));

        *ptr = new;
    }

    return NULL;
}

static inline union kmem_bufctl *
kmem_buf_to_bufctl(void *buf, struct kmem_cache *cache)
{
    return (union kmem_bufctl *)(buf + cache->bufctl_dist);
}

static inline struct kmem_buftag *
kmem_buf_to_buftag(void *buf, struct kmem_cache *cache)
{
    return (struct kmem_buftag *)(buf + cache->buftag_dist);
}

static inline void *
kmem_bufctl_to_buf(union kmem_bufctl *bufctl, struct kmem_cache *cache)
{
    return (void *)bufctl - cache->bufctl_dist;
}

static void
kmem_slab_create_verify(struct kmem_slab *slab, struct kmem_cache *cache)
{
    struct kmem_buftag *buftag;
    size_t buf_size;
    unsigned long buffers;
    void *buf;

    buf_size = cache->buf_size;
    buf = slab->addr;
    buftag = kmem_buf_to_buftag(buf, cache);

    for (buffers = cache->bufs_per_slab; buffers != 0; buffers--) {
        kmem_buf_fill(buf, KMEM_FREE_PATTERN, cache->bufctl_dist);
        buftag->state = KMEM_BUFTAG_FREE;
        buf += buf_size;
        buftag = kmem_buf_to_buftag(buf, cache);
    }
}

/*
 * Create an empty slab for a cache.
 *
 * The caller must drop all locks before calling this function.
 */
static struct kmem_slab *
kmem_slab_create(struct kmem_cache *cache, size_t color)
{
    struct kmem_slab *slab;
    union kmem_bufctl *bufctl;
    size_t buf_size;
    unsigned long buffers;
    void *slab_buf;

    if (cache->slab_alloc_fn == NULL)
        slab_buf = (void *)vm_kmem_alloc(cache->slab_size);
    else
        slab_buf = (void *)cache->slab_alloc_fn(cache->slab_size);

    if (slab_buf == NULL)
        return NULL;

    if (cache->flags & KMEM_CF_SLAB_EXTERNAL) {
        assert(!(cache->flags & KMEM_CF_NO_RECLAIM));
        slab = kmem_cache_alloc(&kmem_slab_cache);

        if (slab == NULL) {
            if (cache->slab_free_fn == NULL)
                vm_kmem_free((unsigned long)slab_buf, cache->slab_size);
            else
                cache->slab_free_fn((unsigned long)slab_buf, cache->slab_size);

            return NULL;
        }
    } else {
        slab = (struct kmem_slab *)(slab_buf + cache->slab_size) - 1;
    }

    list_node_init(&slab->list_node);
    rbtree_node_init(&slab->tree_node);
    slab->nr_refs = 0;
    slab->first_free = NULL;
    slab->addr = slab_buf + color;

    buf_size = cache->buf_size;
    bufctl = kmem_buf_to_bufctl(slab->addr, cache);

    for (buffers = cache->bufs_per_slab; buffers != 0; buffers--) {
        bufctl->next = slab->first_free;
        slab->first_free = bufctl;
        bufctl = (union kmem_bufctl *)((void *)bufctl + buf_size);
    }

    if (cache->flags & KMEM_CF_VERIFY)
        kmem_slab_create_verify(slab, cache);

    return slab;
}

static inline int
kmem_slab_use_tree(int flags)
{
    return !(flags & KMEM_CF_DIRECT) || (flags & KMEM_CF_VERIFY);
}

static inline int
kmem_slab_cmp_lookup(const void *addr, const struct rbtree_node *node)
{
    struct kmem_slab *slab;

    slab = rbtree_entry(node, struct kmem_slab, tree_node);

    if (addr == slab->addr)
        return 0;
    else if (addr < slab->addr)
        return -1;
    else
        return 1;
}

static inline int
kmem_slab_cmp_insert(const struct rbtree_node *a, const struct rbtree_node *b)
{
    struct kmem_slab *slab;

    slab = rbtree_entry(a, struct kmem_slab, tree_node);
    return kmem_slab_cmp_lookup(slab->addr, b);
}

static void
kmem_cpu_pool_init(struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
    /* mutex_init(&cpu_pool->mutex); */
    cpu_pool->flags = cache->flags;
    cpu_pool->size = 0;
    cpu_pool->transfer_size = 0;
    cpu_pool->nr_objs = 0;
    cpu_pool->array = NULL;
}

static inline struct kmem_cpu_pool *
kmem_cpu_pool_get(struct kmem_cache *cache)
{
    return &cache->cpu_pools[cpu_id()];
}

static inline void
kmem_cpu_pool_build(struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache,
                    void **array)
{
    cpu_pool->size = cache->cpu_pool_type->array_size;
    cpu_pool->transfer_size = (cpu_pool->size
                               + KMEM_CPU_POOL_TRANSFER_RATIO - 1)
                              / KMEM_CPU_POOL_TRANSFER_RATIO;
    cpu_pool->array = array;
}

static inline void *
kmem_cpu_pool_pop(struct kmem_cpu_pool *cpu_pool)
{
    cpu_pool->nr_objs--;
    return cpu_pool->array[cpu_pool->nr_objs];
}

static inline void
kmem_cpu_pool_push(struct kmem_cpu_pool *cpu_pool, void *obj)
{
    cpu_pool->array[cpu_pool->nr_objs] = obj;
    cpu_pool->nr_objs++;
}

static int
kmem_cpu_pool_fill(struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
    void *obj;
    int i;

    /* mutex_lock(&cache->mutex); */

    for (i = 0; i < cpu_pool->transfer_size; i++) {
        obj = kmem_cache_alloc_from_slab(cache);

        if (obj == NULL)
            break;

        kmem_cpu_pool_push(cpu_pool, obj);
    }

    /* mutex_unlock(&cache->mutex); */

    return i;
}

static void
kmem_cpu_pool_drain(struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
    void *obj;
    int i;

    /* mutex_lock(&cache->mutex); */

    for (i = cpu_pool->transfer_size; i > 0; i--) {
        obj = kmem_cpu_pool_pop(cpu_pool);
        kmem_cache_free_to_slab(cache, obj);
    }

    /* mutex_unlock(&cache->mutex); */
}

static void
kmem_cache_error(struct kmem_cache *cache, void *buf, int error, void *arg)
{
    struct kmem_buftag *buftag;

    printk("kmem: error: cache: %s, buffer: %p\n", cache->name, buf);

    switch(error) {
    case KMEM_ERR_INVALID:
        panic("kmem: freeing invalid address");
        break;
    case KMEM_ERR_DOUBLEFREE:
        panic("kmem: attempting to free the same address twice");
        break;
    case KMEM_ERR_BUFTAG:
        buftag = arg;
        panic("kmem: invalid buftag content, buftag state: %p",
              (void *)buftag->state);
        break;
    case KMEM_ERR_MODIFIED:
        panic("kmem: free buffer modified, fault address: %p, "
              "offset in buffer: %td", arg, arg - buf);
        break;
    case KMEM_ERR_REDZONE:
        panic("kmem: write beyond end of buffer, fault address: %p, "
              "offset in buffer: %td", arg, arg - buf);
        break;
    default:
        panic("kmem: unknown error");
    }

    /*
     * Never reached.
     */
}

/*
 * Compute an appropriate slab size for the given cache.
 *
 * Once the slab size is known, this function sets the related properties
 * (buffers per slab and maximum color). It can also set the KMEM_CF_DIRECT
 * and/or KMEM_CF_SLAB_EXTERNAL flags depending on the resulting layout.
 */
static void
kmem_cache_compute_sizes(struct kmem_cache *cache, int flags)
{
    size_t i, buffers, buf_size, slab_size, free_slab_size, optimal_size;
    size_t waste, waste_min;
    int embed, optimal_embed = optimal_embed;

    buf_size = cache->buf_size;

    if (buf_size < KMEM_BUF_SIZE_THRESHOLD)
        flags |= KMEM_CACHE_NOOFFSLAB;

    i = 0;
    waste_min = (size_t)-1;

    do {
        i++;
        slab_size = P2ROUND(i * buf_size, PAGE_SIZE);
        free_slab_size = slab_size;

        if (flags & KMEM_CACHE_NOOFFSLAB)
            free_slab_size -= sizeof(struct kmem_slab);

        buffers = free_slab_size / buf_size;
        waste = free_slab_size % buf_size;

        if (buffers > i)
            i = buffers;

        if (flags & KMEM_CACHE_NOOFFSLAB)
            embed = 1;
        else if (sizeof(struct kmem_slab) <= waste) {
            embed = 1;
            waste -= sizeof(struct kmem_slab);
        } else {
            embed = 0;
        }

        if (waste <= waste_min) {
            waste_min = waste;
            optimal_size = slab_size;
            optimal_embed = embed;
        }
    } while ((buffers < KMEM_MIN_BUFS_PER_SLAB)
             && (slab_size < KMEM_SLAB_SIZE_THRESHOLD));

    assert(!(flags & KMEM_CACHE_NOOFFSLAB) || optimal_embed);

    cache->slab_size = optimal_size;
    slab_size = cache->slab_size - (optimal_embed
                ? sizeof(struct kmem_slab)
                : 0);
    cache->bufs_per_slab = slab_size / buf_size;
    cache->color_max = slab_size % buf_size;

    if (cache->color_max >= PAGE_SIZE)
        cache->color_max = PAGE_SIZE - 1;

    if (optimal_embed) {
        if (cache->slab_size == PAGE_SIZE)
            cache->flags |= KMEM_CF_DIRECT;
    } else {
        cache->flags |= KMEM_CF_SLAB_EXTERNAL;
    }
}

void
kmem_cache_init(struct kmem_cache *cache, const char *name, size_t obj_size,
                size_t align, kmem_cache_ctor_t ctor,
                kmem_slab_alloc_fn_t slab_alloc_fn,
                kmem_slab_free_fn_t slab_free_fn, int flags)
{
    struct kmem_cpu_pool_type *cpu_pool_type;
    size_t i, buf_size;

#ifdef KMEM_VERIFY
    cache->flags = KMEM_CF_VERIFY;
#else
    cache->flags = 0;
#endif

    if (flags & KMEM_CACHE_NOCPUPOOL)
        cache->flags |= KMEM_CF_NO_CPU_POOL;

    if (flags & KMEM_CACHE_NORECLAIM) {
        assert(slab_free_fn == NULL);
        flags |= KMEM_CACHE_NOOFFSLAB;
        cache->flags |= KMEM_CF_NO_RECLAIM;
    }

    if (flags & KMEM_CACHE_VERIFY)
        cache->flags |= KMEM_CF_VERIFY;

    if (align < KMEM_ALIGN_MIN)
        align = KMEM_ALIGN_MIN;

    assert(obj_size > 0);
    assert(ISP2(align));
    assert(align < PAGE_SIZE);

    buf_size = P2ROUND(obj_size, align);

    /* mutex_init(&cache->mutex); */
    list_node_init(&cache->node);
    list_init(&cache->partial_slabs);
    list_init(&cache->free_slabs);
    rbtree_init(&cache->active_slabs);
    cache->obj_size = obj_size;
    cache->align = align;
    cache->buf_size = buf_size;
    cache->bufctl_dist = buf_size - sizeof(union kmem_bufctl);
    cache->color = 0;
    cache->nr_objs = 0;
    cache->nr_bufs = 0;
    cache->nr_slabs = 0;
    cache->nr_free_slabs = 0;
    cache->ctor = ctor;
    cache->slab_alloc_fn = slab_alloc_fn;
    cache->slab_free_fn = slab_free_fn;
    strcpy(cache->name, name); /* TODO: strlcpy */
    cache->buftag_dist = 0;
    cache->redzone_pad = 0;

    if (cache->flags & KMEM_CF_VERIFY) {
        cache->bufctl_dist = buf_size;
        cache->buftag_dist = cache->bufctl_dist + sizeof(union kmem_bufctl);
        cache->redzone_pad = cache->bufctl_dist - cache->obj_size;
        buf_size += sizeof(union kmem_bufctl) + sizeof(struct kmem_buftag);
        buf_size = P2ROUND(buf_size, align);
        cache->buf_size = buf_size;
    }

    kmem_cache_compute_sizes(cache, flags);

    for (cpu_pool_type = kmem_cpu_pool_types;
         buf_size <= cpu_pool_type->buf_size;
         cpu_pool_type++);

    cache->cpu_pool_type = cpu_pool_type;

    for (i = 0; i < ARRAY_SIZE(cache->cpu_pools); i++)
        kmem_cpu_pool_init(&cache->cpu_pools[i], cache);

    /* mutex_lock(&kmem_cache_list_mutex); */
    list_insert_tail(&kmem_cache_list, &cache->node);
    /* mutex_unlock(&kmem_cache_list_mutex); */
}

static inline int
kmem_cache_empty(struct kmem_cache *cache)
{
    return cache->nr_objs == cache->nr_bufs;
}

static int
kmem_cache_grow(struct kmem_cache *cache)
{
    struct kmem_slab *slab;
    size_t color;
    int empty;

    /* mutex_lock(&cache->mutex); */

    if (!kmem_cache_empty(cache)) {
        /* mutex_unlock(&cache->mutex); */
        return 1;
    }

    color = cache->color;
    cache->color += cache->align;

    if (cache->color > cache->color_max)
        cache->color = 0;

    /* mutex_unlock(&cache->mutex); */

    slab = kmem_slab_create(cache, color);

    /* mutex_lock(&cache->mutex); */

    if (slab != NULL) {
        list_insert_tail(&cache->free_slabs, &slab->list_node);
        cache->nr_bufs += cache->bufs_per_slab;
        cache->nr_slabs++;
        cache->nr_free_slabs++;
    }

    /*
     * Even if our slab creation failed, another thread might have succeeded
     * in growing the cache.
     */
    empty = kmem_cache_empty(cache);

    /* mutex_unlock(&cache->mutex); */

    return !empty;
}

/*
 * Allocate a raw (unconstructed) buffer from the slab layer of a cache.
 *
 * The cache must be locked before calling this function.
 */
static void *
kmem_cache_alloc_from_slab(struct kmem_cache *cache)
{
    struct kmem_slab *slab;
    union kmem_bufctl *bufctl;

    if (!list_empty(&cache->partial_slabs))
        slab = list_first_entry(&cache->partial_slabs, struct kmem_slab,
                                list_node);
    else if (!list_empty(&cache->free_slabs))
        slab = list_first_entry(&cache->free_slabs, struct kmem_slab, list_node);
    else
        return NULL;

    bufctl = slab->first_free;
    assert(bufctl != NULL);
    slab->first_free = bufctl->next;
    slab->nr_refs++;
    cache->nr_objs++;

    /*
     * The slab has become complete.
     */
    if (slab->nr_refs == cache->bufs_per_slab) {
        list_remove(&slab->list_node);

        if (slab->nr_refs == 1)
            cache->nr_free_slabs--;
    } else if (slab->nr_refs == 1) {
        /*
         * The slab has become partial.
         */
        list_remove(&slab->list_node);
        list_insert_tail(&cache->partial_slabs, &slab->list_node);
        cache->nr_free_slabs--;
    } else if (!list_singular(&cache->partial_slabs)) {
        struct list *node;
        struct kmem_slab *tmp;

        /*
         * The slab remains partial. If there are more than one partial slabs,
         * maintain the list sorted.
         */

        assert(slab->nr_refs > 1);

        for (node = list_prev(&slab->list_node);
             !list_end(&cache->partial_slabs, node);
             node = list_prev(node)) {
            tmp = list_entry(node, struct kmem_slab, list_node);

            if (tmp->nr_refs >= slab->nr_refs)
                break;
        }

        /*
         * If the direct neighbor was found, the list is already sorted.
         * If no slab was found, the slab is inserted at the head of the list.
         */
        if (node != list_prev(&slab->list_node)) {
            list_remove(&slab->list_node);
            list_insert_after(node, &slab->list_node);
        }
    }

    if ((slab->nr_refs == 1) && kmem_slab_use_tree(cache->flags))
        rbtree_insert(&cache->active_slabs, &slab->tree_node,
                      kmem_slab_cmp_insert);

    return kmem_bufctl_to_buf(bufctl, cache);
}

/*
 * Release a buffer to the slab layer of a cache.
 *
 * The cache must be locked before calling this function.
 */
static void
kmem_cache_free_to_slab(struct kmem_cache *cache, void *buf)
{
    struct kmem_slab *slab;
    union kmem_bufctl *bufctl;

    if (cache->flags & KMEM_CF_DIRECT) {
        assert(cache->slab_size == PAGE_SIZE);
        slab = (struct kmem_slab *)P2END((unsigned long)buf, cache->slab_size)
               - 1;
    } else {
        struct rbtree_node *node;

        node = rbtree_lookup_nearest(&cache->active_slabs, buf,
                                     kmem_slab_cmp_lookup, RBTREE_LEFT);
        assert(node != NULL);
        slab = rbtree_entry(node, struct kmem_slab, tree_node);
        assert((unsigned long)buf < (P2ALIGN((unsigned long)slab->addr
                                             + cache->slab_size, PAGE_SIZE)));
    }

    assert(slab->nr_refs >= 1);
    assert(slab->nr_refs <= cache->bufs_per_slab);
    bufctl = kmem_buf_to_bufctl(buf, cache);
    bufctl->next = slab->first_free;
    slab->first_free = bufctl;
    slab->nr_refs--;
    cache->nr_objs--;

    /*
     * The slab has become free.
     */
    if (slab->nr_refs == 0) {
        if (kmem_slab_use_tree(cache->flags))
            rbtree_remove(&cache->active_slabs, &slab->tree_node);

        /*
         * The slab was partial.
         */
        if (cache->bufs_per_slab > 1)
            list_remove(&slab->list_node);

        list_insert_tail(&cache->free_slabs, &slab->list_node);
        cache->nr_free_slabs++;
    } else if (slab->nr_refs == (cache->bufs_per_slab - 1)) {
        /*
         * The slab has become partial.
         */
        list_insert(&cache->partial_slabs, &slab->list_node);
    } else if (!list_singular(&cache->partial_slabs)) {
        struct list *node;
        struct kmem_slab *tmp;

        /*
         * The slab remains partial. If there are more than one partial slabs,
         * maintain the list sorted.
         */

        assert(slab->nr_refs > 0);

        for (node = list_next(&slab->list_node);
             !list_end(&cache->partial_slabs, node);
             node = list_next(node)) {
            tmp = list_entry(node, struct kmem_slab, list_node);

            if (tmp->nr_refs <= slab->nr_refs)
                break;
        }

        /*
         * If the direct neighbor was found, the list is already sorted.
         * If no slab was found, the slab is inserted at the tail of the list.
         */
        if (node != list_next(&slab->list_node)) {
            list_remove(&slab->list_node);
            list_insert_before(node, &slab->list_node);
        }
    }
}

static void
kmem_cache_alloc_verify(struct kmem_cache *cache, void *buf, int construct)
{
    struct kmem_buftag *buftag;
    union kmem_bufctl *bufctl;
    void *addr;

    buftag = kmem_buf_to_buftag(buf, cache);

    if (buftag->state != KMEM_BUFTAG_FREE)
        kmem_cache_error(cache, buf, KMEM_ERR_BUFTAG, buftag);

    addr = kmem_buf_verify_fill(buf, KMEM_FREE_PATTERN, KMEM_UNINIT_PATTERN,
                                cache->bufctl_dist);

    if (addr != NULL)
        kmem_cache_error(cache, buf, KMEM_ERR_MODIFIED, addr);

    addr = buf + cache->obj_size;
    memset(addr, KMEM_REDZONE_BYTE, cache->redzone_pad);

    bufctl = kmem_buf_to_bufctl(buf, cache);
    bufctl->redzone = KMEM_REDZONE_WORD;
    buftag->state = KMEM_BUFTAG_ALLOC;

    if (construct && (cache->ctor != NULL))
        cache->ctor(buf);
}

void *
kmem_cache_alloc(struct kmem_cache *cache)
{
    struct kmem_cpu_pool *cpu_pool;
    int filled;
    void *buf;

    cpu_pool = kmem_cpu_pool_get(cache);

    if (cpu_pool->flags & KMEM_CF_NO_CPU_POOL)
        goto slab_alloc;

    /* mutex_lock(&cpu_pool->mutex); */

fast_alloc:
    if (likely(cpu_pool->nr_objs > 0)) {
        buf = kmem_cpu_pool_pop(cpu_pool);
        /* mutex_unlock(&cpu_pool->mutex); */

        if (cpu_pool->flags & KMEM_CF_VERIFY)
            kmem_cache_alloc_verify(cache, buf, KMEM_AV_CONSTRUCT);

        return buf;
    }

    if (cpu_pool->array != NULL) {
        filled = kmem_cpu_pool_fill(cpu_pool, cache);

        if (!filled) {
            /* mutex_unlock(&cpu_pool->mutex); */

            filled = kmem_cache_grow(cache);

            if (!filled)
                return NULL;

            /* mutex_lock(&cpu_pool->mutex); */
        }

        goto fast_alloc;
    }

    /* mutex_unlock(&cpu_pool->mutex); */

slab_alloc:
    /* mutex_lock(&cache->mutex); */
    buf = kmem_cache_alloc_from_slab(cache);
    /* mutex_unlock(&cache->mutex); */

    if (buf == NULL) {
        filled = kmem_cache_grow(cache);

        if (!filled)
            return NULL;

        goto slab_alloc;
    }

    if (cache->flags & KMEM_CF_VERIFY)
        kmem_cache_alloc_verify(cache, buf, KMEM_AV_NOCONSTRUCT);

    if (cache->ctor != NULL)
        cache->ctor(buf);

    return buf;
}

static void
kmem_cache_free_verify(struct kmem_cache *cache, void *buf)
{
    struct rbtree_node *node;
    struct kmem_buftag *buftag;
    struct kmem_slab *slab;
    union kmem_bufctl *bufctl;
    unsigned char *redzone_byte;
    unsigned long slabend;

    /* mutex_lock(&cache->mutex); */
    node = rbtree_lookup_nearest(&cache->active_slabs, buf,
                                 kmem_slab_cmp_lookup, RBTREE_LEFT);
    /* mutex_unlock(&cache->mutex); */

    if (node == NULL)
        kmem_cache_error(cache, buf, KMEM_ERR_INVALID, NULL);

    slab = rbtree_entry(node, struct kmem_slab, tree_node);
    slabend = P2ALIGN((unsigned long)slab->addr + cache->slab_size, PAGE_SIZE);

    if ((unsigned long)buf >= slabend)
        kmem_cache_error(cache, buf, KMEM_ERR_INVALID, NULL);

    if ((((unsigned long)buf - (unsigned long)slab->addr) % cache->buf_size)
        != 0)
        kmem_cache_error(cache, buf, KMEM_ERR_INVALID, NULL);

    /*
     * As the buffer address is valid, accessing its buftag is safe.
     */
    buftag = kmem_buf_to_buftag(buf, cache);

    if (buftag->state != KMEM_BUFTAG_ALLOC) {
        if (buftag->state == KMEM_BUFTAG_FREE)
            kmem_cache_error(cache, buf, KMEM_ERR_DOUBLEFREE, NULL);
        else
            kmem_cache_error(cache, buf, KMEM_ERR_BUFTAG, buftag);
    }

    redzone_byte = buf + cache->obj_size;
    bufctl = kmem_buf_to_bufctl(buf, cache);

    while (redzone_byte < (unsigned char *)bufctl) {
        if (*redzone_byte != KMEM_REDZONE_BYTE)
            kmem_cache_error(cache, buf, KMEM_ERR_REDZONE, redzone_byte);

        redzone_byte++;
    }

    if (bufctl->redzone != KMEM_REDZONE_WORD) {
        unsigned long word;

        word = KMEM_REDZONE_WORD;
        redzone_byte = kmem_buf_verify_bytes(&bufctl->redzone, &word,
                                             sizeof(bufctl->redzone));
        kmem_cache_error(cache, buf, KMEM_ERR_REDZONE, redzone_byte);
    }

    kmem_buf_fill(buf, KMEM_FREE_PATTERN, cache->bufctl_dist);
    buftag->state = KMEM_BUFTAG_FREE;
}

void
kmem_cache_free(struct kmem_cache *cache, void *obj)
{
    struct kmem_cpu_pool *cpu_pool;
    void **array;

    cpu_pool = kmem_cpu_pool_get(cache);

    if (cpu_pool->flags & KMEM_CF_NO_CPU_POOL)
        goto slab_free;

    if (cpu_pool->flags & KMEM_CF_VERIFY)
        kmem_cache_free_verify(cache, obj);

    /* mutex_lock(&cpu_pool->mutex); */

fast_free:
    if (likely(cpu_pool->nr_objs < cpu_pool->size)) {
        kmem_cpu_pool_push(cpu_pool, obj);
        /* mutex_unlock(&cpu_pool->mutex); */
        return;
    }

    if (cpu_pool->array != NULL) {
        kmem_cpu_pool_drain(cpu_pool, cache);
        goto fast_free;
    }

    /* mutex_unlock(&cpu_pool->mutex); */

    array = kmem_cache_alloc(cache->cpu_pool_type->array_cache);

    if (array != NULL) {
        /* mutex_lock(&cpu_pool->mutex); */

        /*
         * Another thread may have built the CPU pool while the mutex was
         * dropped.
         */
        if (cpu_pool->array != NULL) {
            /* mutex_unlock(&cpu_pool->mutex); */
            kmem_cache_free(cache->cpu_pool_type->array_cache, array);
            goto fast_free;
        }

        kmem_cpu_pool_build(cpu_pool, cache, array);
        goto fast_free;
    }

slab_free:
    kmem_cache_free_to_slab(cache, obj);
}

void
kmem_cache_info(struct kmem_cache *cache)
{
    struct kmem_cache *cache_stats;
    char flags_str[64];

    if (cache == NULL) {
        /* mutex_lock(&kmem_cache_list_mutex); */

        list_for_each_entry(&kmem_cache_list, cache, node)
            kmem_cache_info(cache);

        /* mutex_unlock(&kmem_cache_list_mutex); */

        return;
    }

    cache_stats = kmem_alloc(sizeof(*cache_stats));

    if (cache_stats == NULL) {
        printk("kmem: unable to allocate memory for cache stats\n");
        return;
    }

    /* mutex_lock(&cache->mutex); */
    cache_stats->flags = cache->flags;
    cache_stats->obj_size = cache->obj_size;
    cache_stats->align = cache->align;
    cache_stats->buf_size = cache->buf_size;
    cache_stats->bufctl_dist = cache->bufctl_dist;
    cache_stats->slab_size = cache->slab_size;
    cache_stats->color_max = cache->color_max;
    cache_stats->bufs_per_slab = cache->bufs_per_slab;
    cache_stats->nr_objs = cache->nr_objs;
    cache_stats->nr_bufs = cache->nr_bufs;
    cache_stats->nr_slabs = cache->nr_slabs;
    cache_stats->nr_free_slabs = cache->nr_free_slabs;
    strcpy(cache_stats->name, cache->name);
    cache_stats->buftag_dist = cache->buftag_dist;
    cache_stats->redzone_pad = cache->redzone_pad;
    cache_stats->cpu_pool_type = cache->cpu_pool_type;
    /* mutex_unlock(&cache->mutex); */

    snprintf(flags_str, sizeof(flags_str), "%s%s%s",
        (cache_stats->flags & KMEM_CF_DIRECT) ? " DIRECT" : "",
        (cache_stats->flags & KMEM_CF_SLAB_EXTERNAL) ? " SLAB_EXTERNAL" : "",
        (cache_stats->flags & KMEM_CF_VERIFY) ? " VERIFY" : "");

    printk("kmem: name: %s\n", cache_stats->name);
    printk("kmem: flags: 0x%x%s\n", cache_stats->flags, flags_str);
    printk("kmem: obj_size: %zu\n", cache_stats->obj_size);
    printk("kmem: align: %zu\n", cache_stats->align);
    printk("kmem: buf_size: %zu\n", cache_stats->buf_size);
    printk("kmem: bufctl_dist: %zu\n", cache_stats->bufctl_dist);
    printk("kmem: slab_size: %zu\n", cache_stats->slab_size);
    printk("kmem: color_max: %zu\n", cache_stats->color_max);
    printk("kmem: bufs_per_slab: %lu\n", cache_stats->bufs_per_slab);
    printk("kmem: nr_objs: %lu\n", cache_stats->nr_objs);
    printk("kmem: nr_bufs: %lu\n", cache_stats->nr_bufs);
    printk("kmem: nr_slabs: %lu\n", cache_stats->nr_slabs);
    printk("kmem: nr_free_slabs: %lu\n", cache_stats->nr_free_slabs);
    printk("kmem: buftag_dist: %zu\n", cache_stats->buftag_dist);
    printk("kmem: redzone_pad: %zu\n", cache_stats->redzone_pad);
    printk("kmem: cpu_pool_size: %d\n", cache_stats->cpu_pool_type->array_size);

    kmem_free(cache_stats, sizeof(*cache_stats));
}

void __init
kmem_bootstrap(void)
{
    /* Make sure a bufctl can always be stored in a buffer */
    assert(sizeof(union kmem_bufctl) <= KMEM_ALIGN_MIN);

    list_init(&kmem_cache_list);
    /* mutex_init(&kmem_cache_list_mutex); */
}

void __init
kmem_setup(void)
{
    struct kmem_cpu_pool_type *cpu_pool_type;
    char name[KMEM_NAME_SIZE];
    size_t i, size;

    for (i = 0; i < ARRAY_SIZE(kmem_cpu_pool_types); i++) {
        cpu_pool_type = &kmem_cpu_pool_types[i];
        cpu_pool_type->array_cache = &kmem_cpu_array_caches[i];
        sprintf(name, "kmem_cpu_array_%d", cpu_pool_type->array_size);
        size = sizeof(void *) * cpu_pool_type->array_size;
        kmem_cache_init(cpu_pool_type->array_cache, name, size,
                        cpu_pool_type->array_align, NULL, NULL, NULL, 0);
    }

    /*
     * Prevent off slab data for the slab cache to avoid infinite recursion.
     */
    kmem_cache_init(&kmem_slab_cache, "kmem_slab", sizeof(struct kmem_slab),
                    0, NULL, NULL, NULL, KMEM_CACHE_NOOFFSLAB);

    size = 1 << KMEM_CACHES_FIRST_SHIFT;

    for (i = 0; i < ARRAY_SIZE(kmem_caches); i++) {
        sprintf(name, "kmem_%zu", size);
        kmem_cache_init(&kmem_caches[i], name, size, 0, NULL, NULL, NULL, 0);
        size <<= 1;
    }
}

/*
 * Return the kmem cache index matching the given allocation size, which
 * must be strictly greater than 0.
 */
static inline size_t
kmem_get_index(unsigned long size)
{
    assert(size != 0);

    size = (size - 1) >> KMEM_CACHES_FIRST_SHIFT;

    if (size == 0)
        return 0;
    else
        return (sizeof(long) * CHAR_BIT) - __builtin_clzl(size);
}

static void
kmem_alloc_verify(struct kmem_cache *cache, void *buf, size_t size)
{
    size_t redzone_size;
    void *redzone;

    assert(size <= cache->obj_size);

    redzone = buf + size;
    redzone_size = cache->obj_size - size;
    memset(redzone, KMEM_REDZONE_BYTE, redzone_size);
}

void *
kmem_alloc(size_t size)
{
    size_t index;
    void *buf;

    if (size == 0)
        return NULL;

    index = kmem_get_index(size);

    if (index < ARRAY_SIZE(kmem_caches)) {
        struct kmem_cache *cache;

        cache = &kmem_caches[index];
        buf = kmem_cache_alloc(cache);

        if ((buf != NULL) && (cache->flags & KMEM_CF_VERIFY))
            kmem_alloc_verify(cache, buf, size);
    } else {
        buf = (void *)vm_kmem_alloc(size);
    }

  return buf;
}

void *
kmem_zalloc(size_t size)
{
    void *ptr;

    ptr = kmem_alloc(size);

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, size);
    return ptr;
}

static void
kmem_free_verify(struct kmem_cache *cache, void *buf, size_t size)
{
    unsigned char *redzone_byte, *redzone_end;

    assert(size <= cache->obj_size);

    redzone_byte = buf + size;
    redzone_end = buf + cache->obj_size;

    while (redzone_byte < redzone_end) {
        if (*redzone_byte != KMEM_REDZONE_BYTE)
            kmem_cache_error(cache, buf, KMEM_ERR_REDZONE, redzone_byte);

        redzone_byte++;
    }
}

void
kmem_free(void *ptr, size_t size)
{
    size_t index;

    if ((ptr == NULL) || (size == 0))
        return;

    index = kmem_get_index(size);

    if (index < ARRAY_SIZE(kmem_caches)) {
        struct kmem_cache *cache;

        cache = &kmem_caches[index];

        if (cache->flags & KMEM_CF_VERIFY)
            kmem_free_verify(cache, ptr, size);

        kmem_cache_free(cache, ptr);
    } else {
        vm_kmem_free((unsigned long)ptr, size);
    }
}

void
kmem_info(void)
{
    struct kmem_cache *cache, *cache_stats;
    size_t mem_usage, mem_reclaimable;
    int not_reclaimable;

    cache_stats = kmem_alloc(sizeof(*cache_stats));

    if (cache_stats == NULL) {
        printk("kmem: unable to allocate memory for cache stats\n");
        return;
    }

    printk("kmem: cache                  obj slab  bufs   objs   bufs "
           "   total reclaimable\n");
    printk("kmem: name                  size size /slab  usage  count "
           "  memory      memory\n");

    /* mutex_lock(&kmem_cache_list_mutex); */

    list_for_each_entry(&kmem_cache_list, cache, node) {
        /* mutex_lock(&cache->mutex); */
        not_reclaimable = cache->flags & KMEM_CF_NO_RECLAIM;
        cache_stats->obj_size = cache->obj_size;
        cache_stats->slab_size = cache->slab_size;
        cache_stats->bufs_per_slab = cache->bufs_per_slab;
        cache_stats->nr_objs = cache->nr_objs;
        cache_stats->nr_bufs = cache->nr_bufs;
        cache_stats->nr_slabs = cache->nr_slabs;
        cache_stats->nr_free_slabs = cache->nr_free_slabs;
        strcpy(cache_stats->name, cache->name);
        /* mutex_unlock(&cache->mutex); */

        mem_usage = (cache_stats->nr_slabs * cache_stats->slab_size) >> 10;

        if (not_reclaimable)
            mem_reclaimable = 0;
        else
            mem_reclaimable =
                (cache_stats->nr_free_slabs * cache_stats->slab_size) >> 10;

        printk("kmem: %-19s %6zu %3zuk  %4lu %6lu %6lu %7zuk %10zuk\n",
               cache_stats->name, cache_stats->obj_size,
               cache_stats->slab_size >> 10, cache_stats->bufs_per_slab,
               cache_stats->nr_objs, cache_stats->nr_bufs, mem_usage,
               mem_reclaimable);
    }

    /* mutex_unlock(&kmem_cache_list_mutex); */

    kmem_free(cache_stats, sizeof(*cache_stats));
}