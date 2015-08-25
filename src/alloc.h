#ifndef __ALLOC_H__
#define __ALLOC_H__

#include "utility.h"

void *
alloc_hugepages(size_t size);

void
free_hugepages(void *addr);

#endif
