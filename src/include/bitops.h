#ifndef BITOPS_H
#define BITOPS_H

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)

#define BIT(nr)                 (1UL << (nr))
#define BIT_ULL(nr)             (1ULL << (nr))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

static inline void or_32(void *addr, unsigned int val)
{
	*(unsigned int*) addr = *(unsigned int*)addr | val;
}

static inline void or_64(void *addr, unsigned long val)
{
	*(unsigned long*) addr = *(unsigned long*)addr | val;
}

static inline void and_32(void *addr, unsigned int val)
{
	*(unsigned int*) addr = *(unsigned int*)addr & val;
}
#endif
