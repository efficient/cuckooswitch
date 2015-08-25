#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "alloc.h"

void *
alloc_hugepages(size_t size)
{
    struct rte_memzone *memzone = rte_memzone_reserve_aligned(
        "hugepages",
        size,
        SOCKET_ID_ANY,
        RTE_MEMZONE_SIZE_HINT_ONLY,
        64);
    assert(memzone);

    return memzone->addr;

    /* return rte_malloc(NULL, size, 64); */
}

void
free_hugepages(void *addr)
{
    /* rte_free(addr); */
}

/* struct cpu_alloc_arg { */
/*     size_t size; */
/*     void* ret; */
/* }; */

/* static int */
/* cpu_alloc_internal(void* arg) */
/* { */
/*     struct cpu_alloc_arg* cpu_alloc_arg = (struct cpu_alloc_arg*)arg; */
/*     cpu_alloc_arg->ret = rte_malloc(NULL, cpu_alloc_arg->size, 0); */
/*     return 0; */
/* } */

/* void* */
/* cpu_alloc(size_t size, int cpu_id) */
/* { */
/*     struct cpu_alloc_arg cpu_alloc_arg; */
/*     cpu_alloc_arg.size = size; */
/*     if ((unsigned)cpu_id == rte_lcore_id()) { */
/*         cpu_alloc_internal(&cpu_alloc_arg); */
/*     } else { */
/*         rte_eal_remote_launch(cpu_alloc_internal, &cpu_alloc_arg, (unsigned)cpu_id); */
/*         rte_eal_wait_lcore((unsigned)cpu_id); */
/*     } */
/*     return cpu_alloc_arg.ret; */
/* } */
