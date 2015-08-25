#ifndef __BASIC_TYPES_H__
#define __BASIC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#define __STDC_LIMIT_MACROS
#include <stdint.h>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct kvitem {
    u64 key  : 48;
    u16 value: 16;
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* __BASIC_TYPES_H__ */

