/******************************************************************************
 * 2023.07.05 - riscv64: adapt various relocations and jump table
 * ISCAS ISRC Tarsier. <zhangkai@iscas.ac.cn>
 *
 * 2021.10.11 - return: make every return properly other than direct-exit
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - kpatch_elf/arch_elf: enhance kpatch_elf and arch_elf code
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>

#include <gelf.h>
#include <sys/ptrace.h>

#include "include/kpatch_common.h"
#include "include/kpatch_user.h"
#include "include/kpatch_process.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_file.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"
#include "riscv64_imm.h"

/*
 * In PCREL_LO12 relocation entity, its corresponding symbol's value
 * points to the PCREL_HI20 instruction, where the lower part of the
 * immediate is sitting there.
 * Note .rela.kpatch's r_offset is offset to the section.
 */
static unsigned long
find_pcrel_hi_value(GElf_Rela *r, int idx, GElf_Sym *st,
            unsigned long load_offset, unsigned long v)
{
    int i = idx;
    r--;
    for (; i > 0; i--, r--) {
        if ((r->r_offset == v) &&
                (GELF_R_TYPE(r->r_info) == R_RISCV_PCREL_HI20))
            return st[GELF_R_SYM(r->r_info)].st_value;
        if ((r->r_offset == v) &&
                (GELF_R_TYPE(r->r_info) == R_RISCV_TLS_GOT_HI20)) {
            /* see below R_RISCV_TLS_GOT_HI20 */
            if (is_undef_symbol(&st[GELF_R_SYM(r->r_info)]))
                return st[GELF_R_SYM(r->r_info)].st_value;
            else
                return r->r_addend + load_offset;
        }
    }

    /* Should never happen. If did, using 0 address to indicate. */
    kperr("Not found no. %d rela's corresponding PCREL_HI20\n", idx);
    return 0;
}

/*
 * We use jump table to access undefined global symbols. For STT_FUNC,
 * it acts as a PLT and for STT_OBJECT as a GOT.
 * When used as a GOT, that is used for a variable, we need jump table
 * to hold variable's --value--. But now jump table holding is its address!
 * See kpatch_elf.c#L770.
 * We must fetch variable's value, just like dynamic linker COPY, and
 * replace jump tables's holding. The max size limited to 8 bytes by now.
 *
 * In fact, this function should be in kpatch_arch_add_jmp_entry.
 */
static int
adjust_got_jump_table(struct object_file *o, GElf_Sym *s, GElf_Rela *r)
{
    unsigned long v;
    unsigned long rt = GELF_R_TYPE(r->r_info);

    /* I only know these relocs might be GOT access. */
    if (!is_undef_symbol(s) || (GELF_ST_TYPE(s->st_info) != STT_OBJECT) ||
                    ((rt != R_RISCV_HI20) &&
                     (rt != R_RISCV_TLS_GOT_HI20) &&
                     (rt != R_RISCV_RVC_LUI)))
        return 0;

    /* st_size hold symbol actual load address */
    rt = ptrace(PTRACE_PEEKTEXT, o->proc->pid, s->st_size, NULL);
    if ((rt == -1) && errno) {
        kperr("PTRACE_PEEKTEXT error\n");
        return -1;
    }
    /* st_value hold jump table entity address in patient space.
     * The value holdplace is the 3rd long in the entity.
     * Adjust st_value, so the LO12 part can also get correct value. */
    s->st_value += 2 * sizeof(long);
    v = s->st_value - o->kpta - o->kpfile.patch->jmp_offset +
                            (unsigned long)o->jmp_table;
    *(unsigned long *)v = rt;
    return 1;
}

int kpatch_arch_apply_relocate_add(struct object_file *o, GElf_Shdr *relsec)
{
    struct kpatch_file *kp = o->kpfile.patch;
    GElf_Ehdr *ehdr = (void *)kp + kp->kpatch_offset;
    GElf_Rela *relocs = (void *)ehdr + relsec->sh_offset;
    GElf_Shdr *shdr = (void *)ehdr + ehdr->e_shoff;
    GElf_Shdr *symhdr = NULL;
    GElf_Shdr *tshdr = shdr + relsec->sh_info;
    void *t = (void *)ehdr + shdr[relsec->sh_info].sh_offset;
    void *tshdr2 = (void *)shdr[relsec->sh_info].sh_addr;
    int i;
    const char *scnname;
    GElf_Sym *symtable;

    for (i = 1; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symhdr = &shdr[i];
            break;
        }
    }

    if (symhdr == NULL) {
        kperr("symhdr is null, failed to do relocations.\n");
        return -1;
    }

    symtable = (GElf_Sym *)((void *)ehdr + symhdr->sh_offset);
    scnname = secname(ehdr, shdr + relsec->sh_info);
    kpdebug("applying relocations to '%s'\n", scnname);

    for (i = 0; i < relsec->sh_size / sizeof(*relocs); i++) {
        GElf_Rela *r = relocs + i;
        GElf_Sym *s;
        unsigned long val;
        void *loc, *loc2;

        if (r->r_offset >= tshdr->sh_size) {
            kperr("Relocation offset for section '%s'"
                  " is at 0x%lx beyond the section size 0x%lx\n",
                  scnname, r->r_offset, tshdr->sh_size);
            return -1;
        }

        /* Location in our address space */
        loc = t + r->r_offset;
        /* Location in target process address space (for relative addressing) */
        loc2 = tshdr2 + r->r_offset;
        s = &symtable[GELF_R_SYM(r->r_info)];
        if ((val = adjust_got_jump_table(o, s, r)) == -1ul)
            return -1;
        else if (val == 1)
            val = s->st_value;
        else
            val = s->st_value + r->r_addend;

        switch (GELF_R_TYPE(r->r_info)) {
        case R_RISCV_NONE:
        /* inner-function, PIC */
        case R_RISCV_BRANCH:
        case R_RISCV_RVC_BRANCH:
        /* PIC */
        case R_RISCV_TPREL_HI20:
        case R_RISCV_TPREL_LO12_I:
        case R_RISCV_TPREL_LO12_S:
        case R_RISCV_TPREL_ADD:
        /* PIC, psABI 1.0-rc4 marked as reserved */
        case R_RISCV_TPREL_I:
        case R_RISCV_TPREL_S:
        case R_RISCV_GPREL_I:
        case R_RISCV_GPREL_S:
        /* http://maskray.me/blog/2021-03-14-the-dark-side-of-riscv-linker-relaxation:
         * `.long   .Lfunc_end0-.Lfunc_begin0`
         * Due to linker relaxation, the length is not a constant, so the
         * label difference will actually produce two relocations, a pair
         * of R_RISCV_ADD32 and R_RISCV_SUB32.
         *
         * Label addition/subtraction must be inner-module. I think it also
         * must generate constant like above, no mater it's generated by
         * assembler or relaxed by linker. */
        case R_RISCV_ADD32:
        case R_RISCV_ADD64:
        case R_RISCV_SUB32:
        case R_RISCV_SUB64:
        /* already consumed by static linker */
        case R_RISCV_RELAX:
            break;
        case R_RISCV_32_PCREL:
            val -= (unsigned long)loc2; // fall through
        case R_RISCV_32:
        case R_RISCV_SET32:
            if ((long)val != (long)(int)val) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned *)loc = val;
            break;
        case R_RISCV_64:
            *(unsigned long *)loc = val;
            break;
        case R_RISCV_JAL:
            val -= (unsigned long)loc2;
            if ((val >> 21) && ((val & 0xfffffffffff00000) !=
                                       0xfffffffffff00000)) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned *)loc = set_jtype_imm(*(unsigned *)loc, val);
            break;
        case R_RISCV_CALL:  // psABI 1.0-rc4 marked as Deprecated
        case R_RISCV_CALL_PLT:
            val -= (unsigned long)loc2;
            if ((long)val != (long)(int)val) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned *)loc = set_utype_imm(*(unsigned *)loc, val);
            *(unsigned *)(loc + 4) = set_itype_imm(*(unsigned *)(loc + 4), val);
            break;
        case R_RISCV_PCREL_HI20:
            val -= (unsigned long)loc2; // fall through
        case R_RISCV_HI20:
            if ((long)val != (long)(int)val) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned *)loc = set_utype_imm(*(unsigned *)loc, val);
            break;
        case R_RISCV_PCREL_LO12_I:
            val = find_pcrel_hi_value(r, i, symtable, o->load_offset,
                                    s->st_value - (unsigned long)tshdr2);
            if (val == 0)
                return -1;
            val -= s->st_value; // fall through
        case R_RISCV_LO12_I:
            *(unsigned *)loc = set_itype_imm(*(unsigned *)loc, val);
            break;
        case R_RISCV_PCREL_LO12_S:
            val = find_pcrel_hi_value(r, i, symtable, o->load_offset,
                                    s->st_value - (unsigned long)tshdr2);
            if (val == 0)
                return -1;
            val -= s->st_value; // fall through
        case R_RISCV_LO12_S:
            *(unsigned *)loc = set_stype_imm(*(unsigned *)loc, val);
            break;
        case R_RISCV_RVC_JUMP:
            if ((val >> 12) && ((val & 0xfffffffffffff800) !=
                                       0xfffffffffffff800)) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned short *)loc = set_cjtype_imm(*(unsigned short *)loc, val);
            break;
        case R_RISCV_RVC_LUI:
            if ((val >> 18) && ((val & 0xfffffffffffe0000) !=
                                       0xfffffffffffe0000)) {
                kperr("no. %d relocation out of range\n", i);
                return -1;
            }
            *(unsigned short *)loc = set_citype_imm(*(unsigned short *)loc, val);
            break;
        case R_RISCV_TLS_GOT_HI20:
            if (!is_undef_symbol(s) && (GELF_ST_TYPE(s->st_info) == STT_TLS)) {
                /* This is already points to an appropriate GOT entry in
                 * the patient's memory. */
                val = r->r_addend + o->load_offset;
            }
            val -= (unsigned long)loc2;
            *(unsigned *)loc = set_utype_imm(*(unsigned *)loc, val);
            break;
        default:
            kperr("Non-supported relocation type: %ld\n", GELF_R_TYPE(r->r_info));
            return -1;
        }
    }

    return 0;
}

/* all undefined global symbols access(GOT/PLT) go through this table */
#define JMP_TABLE_JUMP0  0x00000f97 /* auipc   t6,0x0           */
#define JMP_TABLE_JUMP1  0x010fbf83 /* ld      t6,16(t6) # addr */
#define JMP_TABLE_JUMP2  0x000f8067 /* jr      t6               */
unsigned long kpatch_arch_add_jmp_entry(struct object_file *o, unsigned long addr)
{
    struct kpatch_jmp_table_entry entry;
    int e, *p = (int*)&entry;

    p[0] = JMP_TABLE_JUMP0;
    p[1] = JMP_TABLE_JUMP1;
    p[2] = JMP_TABLE_JUMP2;
    entry.addr = addr;
    if (o->jmp_table == NULL) {
        kperr("JMP TABLE not found\n");
        return 0;
    }

    if (o->jmp_table->cur_entry >= o->jmp_table->max_entry) {
        kperr("JMP TABLE overflow\n");
        return 0;
    }
    e = o->jmp_table->cur_entry++;
    o->jmp_table->entries[e] = entry;
    return (unsigned long)(o->kpta + o->kpfile.patch->jmp_offset + \
            ((void *)&o->jmp_table->entries[e] - (void *)o->jmp_table));
}
