#ifndef __CPU_TICKS_H__
#define __CPU_TICKS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "basic_types.h"

static inline u64
read_cpu_ticks(void)
{
    u32 lo, hi;
    __asm__ __volatile("rdtsc"
                       : "=a" (lo),
                         "=d" (hi));
    return ((u64)hi << 32) | lo;
}

u64
get_cpu_ticks_freq();

#ifdef __cplusplus
}
#endif

#endif
