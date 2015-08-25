#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <pthread.h>

#include "basic_types.h"
#include "hash.h"

#define HASHTABLE_HUGEPAGE
/* #define HASHTABLE_ATOMIC_RW */

#define HASHTABLE_DEFAULT_HASHPOWER (15)

#define HASHTABLE_NUM_BUCKETS(n) ((u64)1 << n)
#define HASHTABLE_BUCKET_BITMASK(n) (HASHTABLE_NUM_BUCKETS(n) - 1)
#define HASHTABLE_BUCKET_NUM_ITEMS (4)

#define HASHTABLE_NUM_CUCKOO_PATH (2)
#define HASHTABLE_MAX_CUCKOO_COUNT (500)

#define HASHTABLE_VC_COUNT ((u32)1 << 13)
#define HASHTABLE_VC_BITMASK (HASHTABLE_VC_COUNT - 1)

struct hashtable_item {
    u64 key : 48;
    u16 value;
} __attribute__((__packed__));

struct hashtable_bucket_entry {
    struct hashtable_item items[HASHTABLE_BUCKET_NUM_ITEMS];
} __attribute__((__packed__));

struct cuckoo_record_entry {
    u32 bucket_id[HASHTABLE_NUM_CUCKOO_PATH];
    u32 item_id[HASHTABLE_NUM_CUCKOO_PATH];
    u64 keys[HASHTABLE_NUM_CUCKOO_PATH];
} __attribute__((__packed__));

struct hashtable {
    int hashpower;
    u64 hashitems;
   
    struct hashtable_bucket_entry *buckets;
    u32 *vc;

    struct cuckoo_record_entry *cuckoo_path;
    u64 kickcount;

    pthread_mutex_t lock;
};

struct hashtable *
hashtable_create(int hashpower, void *preallocated_addr);

void
hashtable_destroy(struct hashtable *table);

int
hashtable_insert(struct hashtable *table, u64 key, u16 value);

int
hashtable_lookup(struct hashtable *table, u64 key, u16 *value);

int
hashtable_lookup_multi(struct hashtable *table, unsigned n, u64 *keys, u16 *values);

#endif /* __HASHTABLE_H__ */

