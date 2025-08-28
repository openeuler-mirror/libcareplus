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
#include "loongarch64_imm.h"


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
static unsigned long adjust_got_jump_table(struct object_file *o,
                                         GElf_Sym *s,
                                         GElf_Rela *r)
{
    switch (GELF_R_TYPE(r->r_info)) {
    case R_LARCH_GOT_PC_HI20:
    case R_LARCH_GOT_PC_LO12:
    case R_LARCH_GOT_HI20:
    case R_LARCH_GOT_LO12:
        return s->st_value + r->r_addend;   
    case R_LARCH_JUMP_SLOT:
        if (s->st_shndx == SHN_UNDEF) {
            if (!s->st_value) {
                kperr("Undefined symbol without jump table entry\n");
                return -1ul;
            }
            return s->st_value;
        }
        break;
    case R_LARCH_TLS_IE_PC_HI20:
    case R_LARCH_TLS_IE_PC_LO12:
    case R_LARCH_TLS_GD_PC_HI20:
    case R_LARCH_TLS_GD_HI20:
    case R_LARCH_TLS_GD_PCREL20_S2:
    case R_LARCH_TLS_LD_PC_HI20:
    case R_LARCH_TLS_LD_HI20:
    case R_LARCH_TLS_LD_PCREL20_S2:
        return r->r_addend + o->load_offset;
    }

    return 0;
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
        case R_LARCH_32:
            *(int32_t *)loc = (int32_t)val;
            break;
        case R_LARCH_64:
            *(int64_t *)loc = val;
            break;
        case R_LARCH_ADD32:
            *(int32_t *)loc += (int32_t)val;
            break;
        case R_LARCH_ADD64:
            *(int64_t *)loc += val;
            break;
        case R_LARCH_SUB32:
            *(int32_t *)loc -= (int32_t)val;
            break;
        case R_LARCH_SUB64:
            *(int64_t *)loc -= val;
            break;
        case R_LARCH_ABS_HI20:
            *(uint32_t *)loc = set_pcrel_imm(*(uint32_t *)loc, val >> 12);
            break;
        case R_LARCH_PCALA_HI20:
            uint32_t imm_pcala_hi20 = (((val + 0x800) & ~0xFFF) - ((uint64_t)loc2 & ~0xFFF)) >> 12;
            *(uint32_t *)loc = set_pcrel_imm(*(uint32_t *)loc, imm_pcala_hi20);
            break;
        case R_LARCH_ABS_LO12:
        case R_LARCH_PCALA_LO12:
            *(uint32_t *)loc = set_2ri12_imm(*(uint32_t *)loc, (int32_t)val);
            break;
        case R_LARCH_B16:
            int64_t off_b16 = (int64_t)(val - (uint64_t)loc2);
            if (off_b16 < -(1<<17) || off_b16 >= (1<<17)) {
                kperr("R_LARCH_B16 relocation out of range: 0x%lx\n", val);
                return -1;
            }
            if (off_b16 & 0x3) {
                kperr("R_LARCH_B16 requires 4-byte alignment\n");
                return -1;
            }
            *(uint32_t *)loc = set_2ri16_imm(*(uint32_t *)loc, (int32_t)off_b16);
            break;
        case R_LARCH_B21:
            int64_t off_b21 = (int64_t)(val - (uint64_t)loc2);
            if (off_b21 < -(1<<22) || off_b21 >= (1<<22)) {
                kperr("R_LARCH_B21 relocation out of range: 0x%lx\n", val);
                return -1;
            }
            if (off_b21 & 0x3) {
                kperr("R_LARCH_B21 requires 4-byte alignment\n");
                return -1;
            }
            *(uint32_t *)loc = set_1ri21_imm(*(uint32_t *)loc, (int32_t)off_b21);
            break;
        case R_LARCH_B26:
            int64_t off_b26 = (int64_t)(val - (uint64_t)loc2);
            if (off_b26 < -(1<<27) || off_b26 >= (1<<27)) {
                kperr("R_LARCH_B26 relocation out of range: 0x%lx\n", val);
                return -1;
            }
            if (off_b26 & 0x3) {
                kperr("R_LARCH_B21 requires 4-byte alignment\n");
                return -1;
            }
            *(uint32_t *)loc = set_i26_imm(*(uint32_t *)loc, (int32_t)off_b26);
            break;
        case R_LARCH_PCREL20_S2:
            val -= (unsigned long)loc2;
            if ((long)val < -(1<<21) || (long)val >= (1<<21)) {
                kperr("R_LARCH_PCREL20_S2 relocation out of range: 0x%lx\n", val);
                return -1;
            }
            if (val & 0x3) {
                kperr("R_LARCH_PCREL20_S2 requires 4-byte alignment\n");
                return -1;
            }
            *(uint32_t *)loc = set_pcrel_imm(*(uint32_t *)loc, (uint32_t)val);
            break;
        case R_LARCH_GOT_PC_HI20:
        case R_LARCH_TLS_IE_PC_HI20:
            int32_t imm_pc_hi20 = (((int64_t)val & ~0xFFF) - ((uint64_t)loc2 & ~0xFFF)) >> 12;
            *(uint32_t *)loc = set_pcrel_imm(*(uint32_t *)loc, imm_pc_hi20);
            break;
        case R_LARCH_GOT_PC_LO12:
        case R_LARCH_TLS_IE_PC_LO12:
            int32_t imm_pc_lo12 = (int64_t)val & 0xFFF;
            *(uint32_t *)loc = set_2ri12_imm(*(uint32_t *)loc, imm_pc_lo12);
            break;
        case R_LARCH_GOT_HI20:
        case R_LARCH_TLS_IE_HI20:
            *(uint32_t *)loc = set_pcrel_imm(*(uint32_t *)loc, (int32_t)val >> 12);
            break;
        case R_LARCH_GOT_LO12:
        case R_LARCH_TLS_IE_LO12:
            *(uint32_t *)loc = set_2ri12_imm(*(uint32_t *)loc, (int32_t)val);
            break;
        case R_LARCH_RELAX:
            break;
        case R_LARCH_NONE:
            break;
        default:
            kperr("Unsupported relocation type: %ld\n", GELF_R_TYPE(r->r_info));
            return -EINVAL;
        }
    }

    return 0;
}

/* all undefined global symbols access(GOT/PLT) go through this table */
#define JMP_TABLE_JUMP0  0x1c00000f  // pcaddu12i $t3, 0
#define JMP_TABLE_JUMP1  0x28c041ef  // ld.d $t3, $t3, 16
#define JMP_TABLE_JUMP2  0x4c0001ed  // jirl $t1, $t3, 0
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
