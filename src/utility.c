#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <errno.h>
#include <xmmintrin.h>

#include "utility.h"

u32 
get_num_cpus()
{
    return get_nprocs();
}

int
bind_cpu(u32 cpu)
{
    u32 n = get_num_cpus();
    int ret;

    if (cpu >= n) {
        errno = -EINVAL;
        return -1;
    }

    cpu_set_t cmask;

    CPU_ZERO(&cmask);
    CPU_SET(cpu, &cmask);

    ret = sched_setaffinity(0, sizeof(cmask), &cmask);

    return ret;
}

void 
prefetch(const void *object, u64 size)
{
    u64 offset = ((u64)object) & 0x3fUL;
    const char *p = (const char *)object - offset;
    u64 i;
    for (i = 0; i < offset + size; i += 64)
        _mm_prefetch(p + i, _MM_HINT_T0);
}

void *
get_file_data(char *file, u32 *file_size_pointer, u32 additional_size)
{
    FILE *fd;
    fd = fopen(file, "rb");
    if (fd == NULL) {
        fprintf(stderr, "cannot open file %s, err=%s\n", file, strerror(errno));
        return NULL;
    }
    fseek(fd, 0, SEEK_END);
    int file_size = ftell(fd);
    void *addr = NULL;

    if (file_size == -1 || file_size == 0) {
        fprintf(stderr, "cannot get lenght of %s, err=%s\n", file, strerror(errno));
        goto error;
    }
    *file_size_pointer = file_size;

    addr = malloc(file_size + additional_size);
    if (addr == NULL) {
        fprintf(stderr, "cannot malloc with size=%u, err=%s\n", file_size + additional_size, strerror(errno));
        goto error;
    }

    fseek(fd, 0, SEEK_SET);
    fread(addr, file_size, 1, fd);
    memset(addr + file_size, 0, additional_size);

error:
    fclose(fd);
    return addr;
}

void
free_file_data(void *file_data)
{
    free(file_data);
}

char *
trim_string(char *p)
{
    char *p2 = p + strlen(p) - 1;
    while (*p == ' ' || *p == '\t' || *p == '\r') p++;
    while (p2 >= p && (*p2 == ' ' || *p2 == '\t' || *p2 == '\r')) {
        *p2 = '\0';
        p2--;
    }
    return p;
}
