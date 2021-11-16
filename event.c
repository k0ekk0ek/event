#include "event.h"

extern inline uint32_t atomic_ld32(const volatile atomic_uint32_t *a);
extern inline void atomic_st32(volatile atomic_uint32_t *a, uint32_t v);
extern inline uint32_t atomic_inc32(volatile atomic_uint32_t *a);
extern inline uint32_t atomic_dec32(volatile atomic_uint32_t *a);
