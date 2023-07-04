/******************************************************************************
 * 2023.07.04 - riscv64: compose instructors with immediate
 * ISCAS ISRC Tarsier. <zhangkai@iscas.ac.cn>
 ******************************************************************************/

#ifndef RISCV64_H
#define RISCV64_H

static inline unsigned
set_utype_imm(unsigned ins, unsigned long imm)
{
    /* + imm[11] to counteract lo12 sign extension in next instruction */
    imm += (imm & 0x800) << 1;
    return (imm & 0xfffff000) | (ins & 0xfff);
}

static inline unsigned
set_itype_imm(unsigned ins, unsigned long imm)
{
    return ((imm & 0xfff) << 20) | (ins & 0xfffff);
}

static inline unsigned
set_stype_imm(unsigned ins, unsigned long imm)
{
    /*                             rs2        rs1   func              opcode
       ins:       imm[11-8,7-5]   1,1111,   1111,1  111,  imm[4-1,0]  111,1111
       ins mask       0        1      f       f    f         0        7    f

       imm bit no.  11-----5   4---0
                    1111,111   1,1111
       imm mask     fe0        1f

    ==>imm bit no.  31----25   11--7
     */
    return (ins & 0x1fff07f) |
           ((imm & 0xfe0) << (31-11)) | ((imm & 0x1f) << (11-4));
}

static inline unsigned
set_jtype_imm(unsigned ins, unsigned long imm)
{
    /*
       imm bit no.  20       19------12    11      10---------1
                    1,       1111,1111,    1       111,1111,111  0
       mask         100000   ff000         800     7fe

    ==>imm bit no.  31       19------12    20      30---------21
     */
    return (ins & 0xfff) |
           ((imm & 0x100000) << (31-20)) | (imm & 0xff000) |
           ((imm & 0x800) << (20-11)) | ((imm & 0x7fe) << (30-10));
}

static inline unsigned
set_btype_imm(unsigned ins, unsigned long imm)
{
    /*                                rs2        rs1   func                opcode
       ins:       imm[12 10-8,7-5]   1,1111,   1111,1  111,  imm[4-1,11]  111,1111
       ins mask          0         1     f       f    f        0         7      f

       imm bit no.  12       11     10----5     4--1
                    1,       1      111,111     1,111  0
       imm mask     1000     800    7e0         1e

    ==>imm bit no.  31       7      30---25     11-8
     */
    return (ins & 0x01fff07f) |
           ((imm & 0x1000) << (31-12)) | ((imm & 0x800) >> (11-7)) |
           ((imm & 0x7e0) << (30-10)) | ((imm & 0x1e) << (11-4));
}

static inline unsigned short
set_cjtype_imm(unsigned short ins, unsigned long imm)
{
    /*             funct3       imm                          opcode
       ins:         111    offset[11,4 9 8 10, 6 7 3 2, 1 5]  11
       ins mask       e                 0         0            3

       imm bit no.  11  10    9-8   7  6  5  4   3-1
                     1   1    11,   1  1  1  1,  111    0
       imm mask     800  400  300   80 40 20 10   e

    ==>imm bit no.  12   8    10-9  6  7  2  11  5-3
     */
    return (ins & 0xe003) |
           ((imm & 0x800) << (12-11)) | ((imm & 0x400) >> (10-8)) |
           ((imm & 0x300) << (10-9)) | ((imm & 0x80) >> (7-6)) |
           ((imm & 0x40) << (7-6)) | ((imm & 0x20) >> (5-2)) |
           ((imm & 0x10) << (11-4)) | ((imm & 0xe) << (5-3));
}

/* Now only support C.LUI */
static inline unsigned short
set_citype_imm(unsigned short ins, unsigned long imm)
{
    /*             funct3  imm[17]     rd       imm[16:12]      opcode
       ins:         111    imm[17],  1111,1  imm[16-14,13-12]     11
       ins mask         e             f       8                 3

       imm bit no.  17     16--12
                     1     1,1111
       imm mask     20000  1f000

    ==>imm bit no.  12     6---2
     */
    return (ins & 0xef83) |
           ((imm & 0x20000) >> (17-12)) | ((imm & 0x1f000) >> (16-6));
}

#endif
