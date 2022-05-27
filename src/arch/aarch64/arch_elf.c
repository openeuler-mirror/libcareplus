/******************************************************************************
 * 2021.10.11 - return: make every return properly other than direct-exit
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - kpatch_elf/arch_elf: enhance kpatch_elf and arch_elf code
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.07 - aarch64/arch_elf: Add ldr and ldrb relocation for aarch64
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.07 - aarch64/arch_elf: Add R_AARCH64_LDST32_ABS_LO12_NC relocation type for arm
 * Huawei Technologies Co., Ltd. <lijiajie11@huawei.com>
 *
 * 2021.09.23 - tls: add support for tls symbol
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.09.23 - arch/aarch64/arch_elf: Add LDR and B instruction relocation
 * Huawei Technologies Co., Ltd. <lijiajie11@huawei.com>
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>

#include <gelf.h>

#include "include/kpatch_common.h"
#include "include/kpatch_user.h"
#include "include/kpatch_process.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_file.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"
#include "include/bitops.h"

static int kpatch_arch_apply_relocate(GElf_Rela *r, GElf_Sym *s,
							void *loc, void *loc2, unsigned long val)
{
	uint32_t mask;
	uint32_t immLo;
	uint32_t immHi;

	switch (GELF_R_TYPE(r->r_info)) {
	case R_AARCH64_NONE:
	case R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
		break;
	case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
		kpdebug("R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: val=0x%lx\n", val);
		val = (val >> 12) - ((unsigned long)loc2 >> 12);
		immLo = (val & 0x3) << 29;
		immHi = (val & 0x1FFFFC) << 3;
		mask = (0x3 << 29) | (0x1FFFFC << 3);
		*(unsigned int*)loc = (*(unsigned int*)loc & ~mask) | immLo | immHi;
		kpdebug("R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	case R_AARCH64_ABS64:
		*(unsigned long *)loc = val;
		kpdebug("R_AARCH64_ABS64: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc,val);
		break;
	case R_AARCH64_ADD_ABS_LO12_NC: {
		/* ADD ins */
		kpdebug("R_AARCH64_ADD_ABS_LO12_NC: val=0x%lx\n", val);
		val = val & 0xfff;
		mask = 0xfff << 10;
		*(unsigned int*)loc &= ~mask;
		or_32(loc, (val & 0xfff) << 10);
		kpdebug("R_AARCH64_ADD_ABS_LO12_NC: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc,val);
		break;
	}
	case R_AARCH64_CALL26: {
		/* BL ins */
		kpdebug("R_AARCH64_CALL26: val=0x%lx\n", val);
		val -= (unsigned long)loc2;
		mask = 0x03FFFFFF;;
		*(unsigned int*)loc &= ~mask;
		or_32(loc, (val >> 2) & mask);
		kpdebug("R_AARCH64_CALL26: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc, val);
		break;
	}
	case R_AARCH64_ADR_PREL_PG_HI21: {
		/* ADRP ins */
		kpdebug("R_AARCH64_ADR_PREL_PG_HI21: val=0x%lx\n", val);
		val = (val >> 12) - ((unsigned long)loc2 >> 12);
		immLo = (val & 0x3) << 29;
		immHi = (val & 0x1FFFFC) << 3;
		mask = (0x3 << 29) | (0x1FFFFC << 3);
		*(unsigned int*)loc = (*(unsigned int*)loc & ~mask) | immLo | immHi;
		kpdebug("R_AARCH64_ADR_PREL_PG_HI21: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	case R_AARCH64_ADR_GOT_PAGE: {
		/* ADRP ins  */
		kpdebug("R_AARCH64_ADR_GOT_PAGE: val=0x%lx\n", val);
		val = (val >> 12) - ((unsigned long)loc2 >> 12);
		immLo = (val & 0x3) << 29;
		immHi = (val & 0x1FFFFC) << 3;
		mask = (0x3 << 29) | (0x1FFFFC << 3);
		*(unsigned int*)loc = (*(unsigned int*)loc & ~mask) | immLo | immHi;
		kpdebug("R_AARCH64_ADR_GOT_PAGE: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	case R_AARCH64_LD64_GOT_LO12_NC: {
		/* LDR ins
		 * For function, because we don't use GOT in patch code,
		 * so chang LDR to ADD.
		 * For object, we use jmp table instead GOT, so keep using LDR.
		 */
		kpdebug("R_AARCH64_LD64_GOT_LO12_NC: val=0x%lx\n", val);
		if (GELF_ST_TYPE(s->st_info) == STT_OBJECT &&
		    s->st_shndx == SHN_UNDEF &&
		    GELF_ST_BIND(s->st_info) == STB_GLOBAL) {
			/* This case is for a new global var from DSO */
			val += 8;
			val = ((val & 0xfff) >> 3) << 10;
			*(unsigned int*)loc = *(unsigned int*)loc & ~(0xfff << 10);
			*(unsigned int*)loc = *(unsigned int*)loc | val;
			break;
		}
		*(unsigned int*)loc = (*(unsigned int*)loc & ~(0x3ff << 22));
		*(unsigned int*)loc = (*(unsigned int*)loc | (0x244 << 22));
		val = val & 0xfff;
		mask = 0xfff << 10;
		*(unsigned int*)loc &= ~mask;
		or_32(loc, (val & 0xfff) << 10);
		kpdebug("R_AARCH64_LD64_GOT_LO12_NC: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	case R_AARCH64_JUMP26: {
		/* B ins  */
		kpdebug("R_AARCH64_JUMP26: val=0x%lx\n", val);
		val = (val >> 2) - ((unsigned long)loc2 >> 2);
		val = val & ~(0x3f << 26);
		*(unsigned int*)loc = *(unsigned int*)loc & (0x3f << 26);
		*(unsigned int*)loc = *(unsigned int*)loc | val;
		kpdebug("R_AARCH64_JUMP26: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	case R_AARCH64_LDST32_ABS_LO12_NC: {
		/* LDR ins */
		val = ((val & 0xfff) >> 3) << 10;
		*(unsigned int*)loc = *(unsigned int*)loc & ~(0xfff << 10);
		*(unsigned int*)loc = *(unsigned int*)loc | val;
		kpdebug("R_AARCH64_LDST32_ABS_LO12_NC: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	case R_AARCH64_LDST64_ABS_LO12_NC: {
		/* LDR ins */
		val = ((val & 0xfff) >> 3) << 10;
		*(unsigned int*)loc = *(unsigned int*)loc & ~(0xfff << 10);
		*(unsigned int*)loc = *(unsigned int*)loc | val;
		kpdebug("R_AARCH64_LDST64_ABS_LO12_NC: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
        }
	case R_AARCH64_LDST8_ABS_LO12_NC: {
		/* LDRB ins */
		val = ((val & 0xfff) >> 3) << 10;
		*(unsigned int*)loc = *(unsigned int*)loc & ~(0xfff << 10);
		*(unsigned int*)loc = *(unsigned int*)loc | val;
		kpdebug("R_AARCH64_LDST8_ABS_LO12_NC: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
        }
	default:
		kperr("unknown relocation type: %ld\n", GELF_R_TYPE(r->r_info));
		return -1;
	}
	return 0;
}

int kpatch_arch_apply_relocate_add(struct object_file *o, GElf_Shdr *relsec)
{
	struct kpatch_file *kp = o->kpfile.patch;
	GElf_Ehdr *ehdr = (void *)kp + kp->kpatch_offset;
	GElf_Shdr *shdr = (void *)ehdr + ehdr->e_shoff;
	GElf_Shdr *symhdr = NULL;
	GElf_Rela *relocs = (void *)ehdr + relsec->sh_offset;
	GElf_Shdr *tshdr = shdr + relsec->sh_info;
	void *t = (void *)ehdr + shdr[relsec->sh_info].sh_offset;
	void *tshdr2 = (void *)shdr[relsec->sh_info].sh_addr;
	int i, is_kpatch_info;
	const char *scnname;

	for (i = 1; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB)
			symhdr = &shdr[i];
	}

	if (symhdr == NULL) {
		kperr("symhdr is null, failed to do relocations.\n");
		return -1;
	}

	scnname = secname(ehdr, shdr + relsec->sh_info);
	kpdebug("applying relocations to '%s'\n", scnname);
	is_kpatch_info = strcmp(scnname, ".kpatch.info") == 0;

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
		s = (GElf_Sym *)((void *)ehdr + symhdr->sh_offset) + GELF_R_SYM(r->r_info);
		val = s->st_value + r->r_addend;

		if (is_kpatch_info && is_undef_symbol(s)) {
			val = s->st_size;
		}
		/*
		   Special care for TLS symbol
		   i.  For GLOBAL TLS symbol, point to GOT entry
		   ii. For LOCAL TLS symbol, do nothing since everything is done in static-link
		 */
		if (GELF_ST_TYPE(s->st_info) == STT_TLS) {
			if (GELF_ST_BIND(s->st_info) == STB_LOCAL)
				return 0;
			else
				val = r->r_addend + o->load_offset;
		}

		if(kpatch_arch_apply_relocate(r, s, loc, loc2, val)) {
			return -1;
		}
	}

	return 0;
}


#define JMP_TABLE_JUMP  0xd61f022058000051 /*  ldr x17 #8; br x17 */
unsigned long kpatch_arch_add_jmp_entry(struct object_file *o, unsigned long addr)
{
	struct kpatch_jmp_table_entry entry = {JMP_TABLE_JUMP, addr};
	int e;

	if (o->jmp_table == NULL) {
		kperr("JMP TABLE not found\n");
		return 0;
	}

	if (o->jmp_table->cur_entry >= o->jmp_table->max_entry)
		return 0;
	e = o->jmp_table->cur_entry++;
	o->jmp_table->entries[e] = entry;
	return (unsigned long)(o->kpta + o->kpfile.patch->jmp_offset + \
			((void *)&o->jmp_table->entries[e] - (void *)o->jmp_table));
}
