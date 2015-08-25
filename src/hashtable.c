#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include <rte_malloc.h>

#include "hashtable.h"
#include "alloc.h"
#include "utility.h"

#define HASHTABLE_BUCKET(table, bucket_id) (table->buckets[bucket_id])
#define HASHTABLE_KEY(table, bucket_id, item_id) (table->buckets[bucket_id].items[item_id].key)
#define HASHTABLE_VALUE(table, bucket_id, item_id) (table->buckets[bucket_id].items[item_id].value)
#define HASHTABLE_IS_SLOT_EMPTY(table, bucket_id, item_id) (HASHTABLE_KEY(table, bucket_id, item_id) == 0)

#define begin_read_vc(table, bucket_id1, version1, bucket_id2, version2) \
    do {                                                                \
        version1 = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]); \
        version2 = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id2 & HASHTABLE_VC_BITMASK]); \
        compiler_fence();                                               \
    } while (0)                                                         \
        
#define end_read_vc(table, bucket_id1, version1, bucket_id2, version2) \
    do {                                                                \
        compiler_fence();                                               \
        version1 = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]); \
        version2 = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id2 & HASHTABLE_VC_BITMASK]); \
    } while (0)                                                         \
        
#define begin_inc_vc_single_bucket(table, bucket_id)                    \
    do {                                                                \
        ((volatile u32 *)table->vc)[bucket_id & HASHTABLE_VC_BITMASK]++; \
        compiler_fence();                                               \
    } while (0)                                                         \
        
#define end_inc_vc_single_bucket(table, bucket_id)                      \
    do {                                                                \
        compiler_fence();                                               \
        ((volatile u32 *)table->vc)[bucket_id & HASHTABLE_VC_BITMASK]++; \
    } while (0)                                                         \
        
#define begin_inc_vc(table, bucket_id1, bucket_id2)                    \
    do {                                                                \
        if (expect_true((bucket_id1 & HASHTABLE_VC_BITMASK) != (bucket_id2 & HASHTABLE_VC_BITMASK))) { \
            ((volatile u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]++; \
            ((volatile u32 *)table->vc)[bucket_id2 & HASHTABLE_VC_BITMASK]++; \
        } else {                                                        \
            ((volatile u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]++; \
        }                                                               \
        compiler_fence();                                               \
    } while (0)                                                         \
        
#define end_inc_vc(table, bucket_id1, bucket_id2)                       \
    do {                                                                \
        compiler_fence();                                               \
        if (expect_true((bucket_id1 & HASHTABLE_VC_BITMASK) != (bucket_id2 & HASHTABLE_VC_BITMASK))) { \
            ((volatile u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]++; \
            ((volatile u32 *)table->vc)[bucket_id2 & HASHTABLE_VC_BITMASK]++; \
        } else {                                                        \
            ((volatile u32 *)table->vc)[bucket_id1 & HASHTABLE_VC_BITMASK]++; \
        }                                                               \
    } while (0)                                                         \
        
#define begin_read_vc_multi(table, n, bucket_id1, begin_version1, bucket_id2, begin_version2) \
    do {                                                                \
        unsigned i;                                                     \
        for (i = 0; i < n; i++) {                                       \
            begin_version1[i] = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id1[i] & HASHTABLE_VC_BITMASK]); \
            begin_version2[i] = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id2[i] & HASHTABLE_VC_BITMASK]); \
        }                                                               \
        compiler_fence();                                               \
    } while (0)                                                         \
        
#define end_read_vc_multi(table, n, bucket_id1, end_version1, bucket_id2, end_version2) \
    do {                                                                \
        unsigned i;                                                     \
        compiler_fence();                                               \
        for (i = 0; i < n; i++) {                                       \
            end_version1[i] = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id1[i] & HASHTABLE_VC_BITMASK]); \
            end_version2[i] = *(volatile u32 *)(&((u32 *)table->vc)[bucket_id2[i] & HASHTABLE_VC_BITMASK]); \
        }                                                               \
    } while (0)                                                         \
        
#define atomic_read_vc(table, bucket_id1, version1, bucket_id2, version2) \
    do {                                                                \
        version1 = __sync_fetch_and_add(&table->vc[bucket_id1 & HASHTABLE_VC_BITMASK], 0); \
        version2 = __sync_fetch_and_add(&table->vc[bucket_id2 & HASHTABLE_VC_BITMASK], 0); \
    } while (0)                                                         \
        
#define atomic_inc_vc(table, bucket_id1, bucket_id2)                    \
    do {                                                                \
        __sync_fetch_and_add(&table->vc[bucket_id1 & HASHTABLE_VC_BITMASK], 1); \
        __sync_fetch_and_add(&table->vc[bucket_id2 & HASHTABLE_VC_BITMASK], 1); \
    } while (0)                                                         \
        
static inline u32
hashed_key(u64 key)
{
    /* return (u32 *)(key & 0xFFFFFFFF); */
    /* return city_hash((const char *)&key, 6); */
    return (u32)hash_crc_u64(key, 0xbc9f1d34);
    /* return (u32)hash_crc((const char *)&key, 6, 0xbc9f1d34); */
}

static inline u32
get_bucket_id(struct hashtable *table, u32 h)
{
    return h & HASHTABLE_BUCKET_BITMASK(table->hashpower);
}

static inline u32
get_buddy_bucket_id(struct hashtable *table, u32 h, u32 bucket_id)
{
    u32 tag = h >> 12;
    return (bucket_id ^ ((tag + 1) * 0x5bd1e995)) & HASHTABLE_BUCKET_BITMASK(table->hashpower);
}

static inline int
bucket_lookup(struct hashtable *table, u64 key, u16 *value, u32 bucket_id)
{
    int i;

    for (i = 0; i < HASHTABLE_BUCKET_NUM_ITEMS; i++)
        if (HASHTABLE_KEY(table, bucket_id, i) == key) {
            *value = HASHTABLE_VALUE(table, bucket_id, i);
            return 1;
        }
    return 0;
}

static int
bucket_insert(struct hashtable *table, u64 key, u16 value, u32 bucket_id)
{
    int i;

    for (i = 0; i < HASHTABLE_BUCKET_NUM_ITEMS; i++) {
        if (HASHTABLE_IS_SLOT_EMPTY(table, bucket_id, i)) {
            begin_inc_vc_single_bucket(table, bucket_id);
            HASHTABLE_KEY(table, bucket_id, i) = key;
            HASHTABLE_VALUE(table, bucket_id, i) = value;
            end_inc_vc_single_bucket(table, bucket_id);
            return 1;
        }
        if (HASHTABLE_KEY(table, bucket_id, i) == key) {
            begin_inc_vc_single_bucket(table, bucket_id);
            HASHTABLE_KEY(table, bucket_id, i) = key;
            HASHTABLE_VALUE(table, bucket_id, i) = value;
            end_inc_vc_single_bucket(table, bucket_id);
            return -1;
        }
    }
    return 0;
}

struct hashtable *
hashtable_create(int hashpower, void *preallocated_addr)
{
    struct hashtable *table = (struct hashtable *)malloc(sizeof(struct hashtable));
    if (!table)
        goto cleanup;

    table->hashpower = (hashpower > 0) ? hashpower : HASHTABLE_DEFAULT_HASHPOWER;
    table->hashitems = 0;
    table->kickcount = 0;

    void *addr;
#ifndef HASHTABLE_HUGEPAGE
    printf("allocating normal pages\n");
    posix_memalign((void **)&addr, 64, HASHTABLE_NUM_BUCKETS(table->hashpower) * sizeof(struct hashtable_bucket_entry));
    table->buckets = (struct hashtable_bucket_entry *)addr;
#else
    printf("allocating huge pages\n");
    if (!preallocated_addr)
        addr = alloc_hugepages((size_t)HASHTABLE_NUM_BUCKETS(table->hashpower) * sizeof(struct hashtable_bucket_entry));
    else
        addr = preallocated_addr;
    table->buckets = (struct hashtable_bucket_entry *)addr;
#endif
    memset(table->buckets, 0, HASHTABLE_NUM_BUCKETS(table->hashpower) * sizeof(struct hashtable_bucket_entry));
    printf("size=%.2lfKB\n", (double)HASHTABLE_NUM_BUCKETS(table->hashpower) * sizeof(struct hashtable_bucket_entry) / 1024);
    if (!table->buckets)
        goto cleanup;

    table->vc = (u32 *)malloc(HASHTABLE_VC_COUNT * sizeof(u32));
    if (!table->vc)
        goto cleanup;

    table->cuckoo_path = (struct cuckoo_record_entry *)malloc(HASHTABLE_MAX_CUCKOO_COUNT * sizeof(struct cuckoo_record_entry));
    if (!table->cuckoo_path)
        goto cleanup;

    memset(table->buckets, 0, HASHTABLE_NUM_BUCKETS(table->hashpower) * sizeof(struct hashtable_bucket_entry));
    memset(table->vc, 0, HASHTABLE_VC_COUNT * sizeof(u32));
    memset(table->cuckoo_path, 0, HASHTABLE_MAX_CUCKOO_COUNT * sizeof(struct cuckoo_record_entry));
    pthread_mutex_init(&table->lock, NULL);

    return table;

cleanup:
    if (table) {
        free(table->cuckoo_path);
        free(table->vc);
#ifndef HASHTABLE_HUGEPAGE
        free(table->buckets);
#else
        free_hugepages(table->buckets);
#endif
    }
    free(table);

    return NULL;
}

void
hashtable_destroy(struct hashtable *table)
{
    free(table->cuckoo_path);
    free(table->vc);
#ifndef HASHTABLE_HUGEPAGE
    free(table->buckets);
#else
    free_hugepages(table->buckets);
#endif
    free(table);
}

static int
cuckoo_path_search(struct hashtable *table, int begin_depth, int *out_path_index)
{
    int i, path_index;
    int depth = begin_depth;

    while ((table->kickcount < HASHTABLE_MAX_CUCKOO_COUNT) && (depth >= 0) && (depth < HASHTABLE_MAX_CUCKOO_COUNT - 1)) {
        struct cuckoo_record_entry *cur = table->cuckoo_path + depth;
        struct cuckoo_record_entry *next = table->cuckoo_path + depth + 1;

        for (path_index = 0; path_index < HASHTABLE_NUM_CUCKOO_PATH; path_index++) {
            u32 bucket_id = cur->bucket_id[path_index];

            for (i = 0; i < HASHTABLE_BUCKET_NUM_ITEMS; i++)
                if (HASHTABLE_IS_SLOT_EMPTY(table, bucket_id, i)) {
                    cur->item_id[path_index] = i;
                    *out_path_index = path_index;
                    return depth;
                }

            i = rand() % HASHTABLE_BUCKET_NUM_ITEMS;
            cur->item_id[path_index] = i;
            cur->keys[path_index] = HASHTABLE_KEY(table, bucket_id, i);

            u32 h = hashed_key(cur->keys[path_index]);
            next->bucket_id[path_index] = get_buddy_bucket_id(table, h, bucket_id);
        }

        table->kickcount += HASHTABLE_NUM_CUCKOO_PATH;
        depth++;
    }

    return -1;
}

static int
cuckoo_path_move(struct hashtable *table, int begin_depth, int path_index)
{
    int depth = begin_depth;

    while (depth > 0) {
        struct cuckoo_record_entry *from = table->cuckoo_path + depth - 1;
        u32 from_bucket_id = from->bucket_id[path_index], from_item_id = from->item_id[path_index];

        struct cuckoo_record_entry *to = table->cuckoo_path + depth;
        u32 to_bucket_id = to->bucket_id[path_index], to_item_id = to->item_id[path_index];

        if (HASHTABLE_KEY(table, from_bucket_id, from_item_id) != from->keys[path_index])
            return depth;

#ifdef HASHTABLE_ATOMIC_RW
        atomic_inc_vc(table, from_bucket_id, to_bucket_id);
#else
        begin_inc_vc(table, from_bucket_id, to_bucket_id);
#endif
        HASHTABLE_KEY(table, to_bucket_id, to_item_id) = HASHTABLE_KEY(table, from_bucket_id, from_item_id);
        HASHTABLE_VALUE(table, to_bucket_id, to_item_id) = HASHTABLE_VALUE(table, from_bucket_id, from_item_id);
        HASHTABLE_KEY(table, from_bucket_id, from_item_id) = 0;
        HASHTABLE_VALUE(table, from_bucket_id, from_item_id) = 0;
#ifdef HASHTABLE_ATOMIC_RW
        atomic_inc_vc(table, from_bucket_id, to_bucket_id);
#else
        end_inc_vc(table, from_bucket_id, to_bucket_id);
#endif

        depth--;
    }

    return depth;
}

static int
run_cuckoo(struct hashtable *table, u32 bucket_id1, u32 bucket_id2)
{
    int i, depth = 0;

    for (i = 0; i < HASHTABLE_NUM_CUCKOO_PATH; i++) {
        if (i < HASHTABLE_NUM_CUCKOO_PATH /2 )
            table->cuckoo_path[depth].bucket_id[i] = bucket_id1;
        else
            table->cuckoo_path[depth].bucket_id[i] = bucket_id2;
    }

    table->kickcount = 0;
    while (1) {
        int c = cuckoo_path_search(table, depth, &i);
        if (c < 0)
            return -1;
        c = cuckoo_path_move(table, c, i);
        if (c == 0)
            return i;
        depth = c - 1;
    }

    return -1;
}

static int
hashtable_insert_internal(struct hashtable *table, u64 key, u16 value, u32 bucket_id1, u32 bucket_id2)
{
    int r;

    if (r = bucket_insert(table, key, value, bucket_id1))
        return r;
    if (r = bucket_insert(table, key, value, bucket_id2))
        return r;

    int bucket_id = run_cuckoo(table, bucket_id1, bucket_id2);
    if (bucket_id >= 0)
        if (r = bucket_insert(table, key, value, table->cuckoo_path[0].bucket_id[bucket_id]))
            return r;

    return 0;
}

int
hashtable_insert(struct hashtable *table, u64 key, u16 value)
{
    /* while (pthread_mutex_trylock(&table->lock)) {}; */

    u32 h = hashed_key(key);
    u32 bucket_id1 = get_bucket_id(table, h);
    u32 bucket_id2 = get_buddy_bucket_id(table, h, bucket_id1);

    int r = hashtable_insert_internal(table, key, value, bucket_id1, bucket_id2);

    if (r >= 0)
        table->hashitems += r;

    /* pthread_mutex_unlock(&table->lock); */

    return r;
}

int
hashtable_lookup(struct hashtable *table, u64 key, u16 *value)
{
    u32 h = hashed_key(key);
    u32 bucket_id1 = get_bucket_id(table, h);
    u32 bucket_id2 = get_buddy_bucket_id(table, h, bucket_id1);

    int r;
    u32 begin_version1, begin_version2;
    u32 end_version1, end_version2;

restart:
#ifdef HASHTABLE_ATOMIC_RW
    atomic_read_vc(table, bucket_id1, begin_version1, bucket_id2, begin_version2);
#else
    begin_read_vc(table, bucket_id1, begin_version1, bucket_id2, begin_version2);
#endif
    if (((begin_version1 & 1) == 1) || ((begin_version2 & 1) == 1))
        goto restart;
    r = bucket_lookup(table, key, value, bucket_id1);
    if (!r)
        r = bucket_lookup(table, key, value, bucket_id2);
#ifdef HASHTABLE_ATOMIC_INSTR
    atomic_read_vc(table, bucket_id1, end_version1, bucket_id2, end_version2);
#else
    end_read_vc(table, bucket_id1, end_version1, bucket_id2, end_version2);
#endif
    if ((begin_version1 != end_version1) || (begin_version2 != end_version2))
        goto restart;

    return r;
}

int
hashtable_lookup_multi(struct hashtable *table, unsigned n, u64 *keys, u16 *values)
{
    u32 h[n];
    u32 bucket_id1[n];
    u32 bucket_id2[n];
    unsigned i;
  
    for (i = 0; i < n; i++) {
        h[i] = hashed_key(keys[i]);
        bucket_id1[i] = get_bucket_id(table, h[i]);
        bucket_id2[i] = get_buddy_bucket_id(table, h[i], bucket_id1[i]);
        prefetch((const void *)&table->buckets[bucket_id1[i]], sizeof(struct hashtable_bucket_entry));
    }

    unsigned r[n];
    u32 begin_version1[n], begin_version2[n];
    u32 end_version1[n], end_version2[n];

restart:
    begin_read_vc_multi(table, n, bucket_id1, begin_version1, bucket_id2, begin_version2);

    for (i = 0; i < n; i++)
        if (((begin_version1[i] & 1) == 1) || ((begin_version2[i] & 1) == 1))
            break;
    if (i < n) goto restart;

    /* for (i = 0; i < n; i++) { */
    /*     /\* void *addr = &HASHTABLE_BUCKET(table, bucket_id1[i]); *\/ */
    /*     /\* asm volatile ("movl (%0), %%eax\n\t" *\/ */
    /*     /\*               : *\/ */
    /*     /\*               : "r"(addr) *\/ */
    /*     /\*               : "eax"); *\/ */
    /*     prefetch((const void *)&table->buckets[bucket_id1[i]], sizeof(struct hashtable_bucket_entry)); */
    /* } */

    for (i = 0; i < n; i++) {
        r[i] = bucket_lookup(table, keys[i], &values[i], bucket_id1[i]);
        if (!r[i])
            prefetch((const void *)&table->buckets[bucket_id2[i]], sizeof(struct hashtable_bucket_entry));
    }

    /* for (i = 0; i < n; i++) { */
    /*     if (r[i]) */
    /*         continue; */
        
    /*     /\* void *addr = &HASHTABLE_BUCKET(table, bucket_id2[i]); *\/ */
    /*     /\* asm volatile ("movl (%0), %%eax\n\t" *\/ */
    /*     /\*               : *\/ */
    /*     /\*               : "r"(addr) *\/ */
    /*     /\*               : "eax"); *\/ */
    /*     prefetch((const void *)&table->buckets[bucket_id2[i]], sizeof(struct hashtable_bucket_entry)); */
    /* } */

    for (i = 0; i < n; i++)
        if (!r[i]) r[i] = bucket_lookup(table, keys[i], &values[i], bucket_id2[i]);

    end_read_vc_multi(table, n, bucket_id1, end_version1, bucket_id2, end_version2);

    for (i = 0; i < n; i++)
        if ((begin_version1[i] != end_version1[i]) || (begin_version2[i] != end_version2[i]))
            break;
    if (i < n) goto restart;
    
    int count = 0;
    for (i = 0; i < n; i++)
        count += r[i];
    return count;
}
