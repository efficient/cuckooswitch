#include "hash.h"

#include <string.h>

static u32 UNALIGNED_LOAD32(const char *p) {
  u32 result;
  memcpy(&result, p, sizeof(result));
  return result;
}

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#else

#include <byteswap.h>

#endif

#ifdef ENDIAN_BIG
#define u32_in_expected_order(x) (bswap_32(x))
#define u64_in_expected_order(x) (bswap_64(x))
#else
#define u32_in_expected_order(x) (x)
#define u64_in_expected_order(x) (x)
#endif

#define LIKELY(x) (__builtin_expect(!!(x), 1))

static u32 Fetch32(const char *p) {
  return u32_in_expected_order(UNALIGNED_LOAD32(p));
}

// Some primes between 2^63 and 2^64 for various uses.
static const u64 k0 = 0xc3a5c85c97cb3127ULL;
static const u64 k1 = 0xb492b66fbe98f273ULL;
static const u64 k2 = 0x9ae16a3b2f90404fULL;

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
static const u32 c1 = 0xcc9e2d51;
static const u32 c2 = 0x1b873593;

// A 32-bit to 32-bit integer hash copied from Murmur3.
static u32 fmix(u32 h)
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

static u32 Rotate32(u32 val, int shift) {
  // Avoid shifting by 32: doing so yields an undefined result.
  return shift == 0 ? val : ((val >> shift) | (val << (32 - shift)));
}

#define swap(x, y) do {x ^= y; y ^= x; x ^= y;} while (0)

#undef PERMUTE3
//#define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)
#define PERMUTE3(a, b, c) do { swap(a, b); swap(a, c); } while (0)

static u32 Mur(u32 a, u32 h) {
  // Helper from Murmur3 for combining two 32-bit values.
  a *= c1;
  a = Rotate32(a, 17);
  a *= c2;
  h ^= a;
  h = Rotate32(h, 19);
  return h * 5 + 0xe6546b64;
}

static u32 Hash32Len13to24(const char *s, size_t len) {
  u32 a = Fetch32(s - 4 + (len >> 1));
  u32 b = Fetch32(s + 4);
  u32 c = Fetch32(s + len - 8);
  u32 d = Fetch32(s + (len >> 1));
  u32 e = Fetch32(s);
  u32 f = Fetch32(s + len - 4);
  u32 h = len;

  return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

static u32 Hash32Len0to4(const char *s, size_t len) {
  u32 b = 0;
  u32 c = 9;
  size_t i;
  for (i = 0; i < len; i++) {
    b = b * c1 + s[i];
    c ^= b;
  }
  return fmix(Mur(b, Mur(len, c)));
}

static u32 Hash32Len5to12(const char *s, size_t len) {
  u32 a = len, b = len * 5, c = 9, d = b;
  a += Fetch32(s);
  b += Fetch32(s + len - 4);
  c += Fetch32(s + ((len >> 1) & 4));
  return fmix(Mur(c, Mur(b, Mur(a, d))));
}

u32 city_hash(const char *s, size_t len) {
  if (len <= 24) {
    return len <= 12 ?
        (len <= 4 ? Hash32Len0to4(s, len) : Hash32Len5to12(s, len)) :
        Hash32Len13to24(s, len);
  }

  // len > 24
  u32 h = len, g = c1 * len, f = g;
  u32 a0 = Rotate32(Fetch32(s + len - 4) * c1, 17) * c2;
  u32 a1 = Rotate32(Fetch32(s + len - 8) * c1, 17) * c2;
  u32 a2 = Rotate32(Fetch32(s + len - 16) * c1, 17) * c2;
  u32 a3 = Rotate32(Fetch32(s + len - 12) * c1, 17) * c2;
  u32 a4 = Rotate32(Fetch32(s + len - 20) * c1, 17) * c2;
  h ^= a0;
  h = Rotate32(h, 19);
  h = h * 5 + 0xe6546b64;
  h ^= a2;
  h = Rotate32(h, 19);
  h = h * 5 + 0xe6546b64;
  g ^= a1;
  g = Rotate32(g, 19);
  g = g * 5 + 0xe6546b64;
  g ^= a3;
  g = Rotate32(g, 19);
  g = g * 5 + 0xe6546b64;
  f += a4;
  f = Rotate32(f, 19);
  f = f * 5 + 0xe6546b64;
  size_t iters = (len - 1) / 20;
  do {
    u32 a0 = Rotate32(Fetch32(s) * c1, 17) * c2;
    u32 a1 = Fetch32(s + 4);
    u32 a2 = Rotate32(Fetch32(s + 8) * c1, 17) * c2;
    u32 a3 = Rotate32(Fetch32(s + 12) * c1, 17) * c2;
    u32 a4 = Fetch32(s + 16);
    h ^= a0;
    h = Rotate32(h, 18);
    h = h * 5 + 0xe6546b64;
    f += a1;
    f = Rotate32(f, 19);
    f = f * c1;
    g += a2;
    g = Rotate32(g, 18);
    g = g * 5 + 0xe6546b64;
    h ^= a3 + a1;
    h = Rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    g ^= a4;
    g = bswap_32(g) * 5;
    h += a4 * 5;
    h = bswap_32(h);
    f += a0;
    PERMUTE3(f, h, g);
    s += 20;
  } while (--iters != 0);
  g = Rotate32(g, 11) * c1;
  g = Rotate32(g, 17) * c1;
  f = Rotate32(f, 11) * c1;
  f = Rotate32(f, 17) * c1;
  h = Rotate32(h + g, 19);
  h = h * 5 + 0xe6546b64;
  h = Rotate32(h, 17) * c1;
  h = Rotate32(h + f, 19);
  h = h * 5 + 0xe6546b64;
  h = Rotate32(h, 17) * c1;
  return h;
}

