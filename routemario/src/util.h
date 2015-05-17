#ifndef UTIL_H
#define UTIL_H

#define ROUNDUP8(x)  (((x) + 7UL) & (~7UL))
#define ROUNDUP16(x) (((x) + 15UL) & (~15UL))
#define ROUNDUP32(x) (((x) + 31UL) & (~31UL))
#define ROUNDUP64(x) (((x) + 63UL) & (~63UL))
#define POWERROUND(x)                                     \
  ({                                                     \
    int fls_bit = generic_fls(x);                         \
    fls_bit = (1 << fls_bit) < x ? fls_bit - 1: fls_bit; \
    1 << fls_bit;                                         \
  })

static inline int
generic_fls(uint32_t x)
{
  int r = 32;
  if (!x) return 0;

  if (!(x & 0xffff0000u)) {
    x <<= 16;
    r -= 16;
  }
  if (!(x & 0xff000000u)) {
    x <<= 8;
    r -= 8;
  }
  if (!(x & 0xf0000000u)) {
    x <<= 4;
    r -= 4;
  }
  if (!(x & 0xc0000000u)) {
    x <<= 2;
    r -= 2;
  }
  if (!(x & 0x80000000u)) {
    x <<= 1;
    r -= 1;
  }
  return r;
}
#endif
