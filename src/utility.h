#ifndef __UTILITY_H__
#define __UTILITY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "basic_types.h"

u32
get_num_cpus();

int
bind_cpu(u32 cpu);

void 
prefetch(const void *object, u64 size);

void *
get_file_data(char *file, u32 *file_size_pointer, u32 additional_size);

void 
free_file_data(void *file_data);

char *
trim_string(char *p);

static inline u16
fastrand(u32 *seed)
{
    *seed = (214013 * (*seed) + 2531011);
    return (*seed >> 16) & 0xFFFF;
}

static inline void
lfence()
{
    __asm__ __volatile("lfence" ::: "memory");
}

static inline void
sfence()
{
    __asm__ __volatile("sfence" ::: "memory");
}

static inline void
mfence()
{
    __asm__ __volatile("mfence" ::: "memory");
}

static inline void
compiler_fence()
{
    __asm__ __volatile("" ::: "memory");
}

#define expect_true(expr) __builtin_expect((expr), 1)
#define expect_false(expr) __builtin_expect((expr), 0)

#ifdef __cplusplus
}
#endif

#endif /* __UTILITY_H__ */
