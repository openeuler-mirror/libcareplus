#ifndef LOONGARCH_IMM_H
#define LOONGARCH_IMM_H

#include <stdint.h>

/* Masks for clearing immediate-fields */
#define LOONG_MASK_TYPE_2RI8 (~(0xFFu << 10))
#define LOONG_MASK_TYPE_2RI12 (~(0xFFFu << 10))
#define LOONG_MASK_TYPE_2RI14 (~(0x3FFFu << 10))
#define LOONG_MASK_TYPE_2RI16 (~(0xFFFFu << 10))
#define LOONG_MASK_1RI21 (~((0xFFFFu << 10) | 0x1Fu))
#define LOONG_MASK_I26 (~((0xFFFFu << 10) | 0x3FFu))
#define LOONG_MASK_PCREL_UTYPE (~(0xFFFFFu << 5))
/* 2RI8-type */
static inline uint32_t set_2ri8_imm(uint32_t ins, uint32_t imm)
{
    return (ins & LOONG_MASK_TYPE_2RI8) | ((imm & 0xFFu) << 10);
}

/* 2RI12-type */
static inline uint32_t set_2ri12_imm(uint32_t ins, uint32_t imm)
{
    return (ins & LOONG_MASK_TYPE_2RI12) | ((imm & 0xFFFu) << 10);
}

/* 2RI14-type */
static inline uint32_t set_2ri14_imm(uint32_t ins, uint32_t imm)
{
    return (ins & LOONG_MASK_TYPE_2RI14) | ((imm & 0x3FFFu) << 10);
}

/* 2RI16-type */
static inline uint32_t set_2ri16_imm(uint32_t ins, uint32_t imm)
{
    return (ins & LOONG_MASK_TYPE_2RI16) | ((imm & 0xFFFFu) << 10);
}

/* 1RI21-type */
static inline uint32_t set_1ri21_imm(uint32_t ins, int32_t offset)
{
    int32_t imm_val = offset >> 2;
    uint32_t imm_lo = (uint32_t)(imm_val & 0xFFFFu) << 10;
    uint32_t imm_hi = ((uint32_t)imm_val >> 16) & 0x1Fu;
    return (ins & LOONG_MASK_1RI21) | imm_lo | imm_hi;
}

/* I26-type */
static inline uint32_t set_i26_imm(uint32_t ins, int32_t offset)
{
    int32_t imm_val = offset >> 2;
    uint32_t imm_lo = (uint32_t)(imm_val & 0xFFFFu) << 10;
    uint32_t imm_hi = ((uint32_t)imm_val >> 16) & 0x3FFu;
    return (ins & LOONG_MASK_I26) | imm_lo | imm_hi;
}

/* PCREL */
static inline uint32_t set_pcrel_imm(uint32_t ins, uint32_t imm)
{

    return (ins & LOONG_MASK_PCREL_UTYPE) | (((imm >> 2) & 0xFFFFFu) << 5);
}

#endif /* LOONGARCH_IMM_H */
