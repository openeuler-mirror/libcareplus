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
	switch (GELF_R_TYPE(r->r_info)) {
	case R_AARCH64_ABS64:
		*(unsigned long *)loc = val;
		kpdebug("R_AARCH64_ABS64: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc,val);
		break;
	case R_AARCH64_ADD_ABS_LO12_NC: {
		//ADD ins
		kpdebug("R_AARCH64_ADD_ABS_LO12_NC: val=0x%lx\n", val);
		val = val & 0xfff;
		uint32_t mask = 0xfff << 10;
		*(unsigned int*)loc &= ~mask;
		or_32(loc, (val & 0xfff) << 10);
		kpdebug("R_AARCH64_ADD_ABS_LO12_NC: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc,val);
		break;
	}
	case R_AARCH64_CALL26: {
		// TODO bl ins
		kpdebug("R_AARCH64_CALL26: val=0x%lx\n", val);
		val -= (unsigned long)loc2;
		uint32_t mask = 0x03FFFFFF;;
		*(unsigned int*)loc &= ~mask;
		or_32(loc, (val >> 2) & mask);
		kpdebug("R_AARCH64_CALL26: loc=0x%x, val =0x%lx\n",*(unsigned int*)loc, val);
		break;
	}
	case R_AARCH64_ADR_PREL_PG_HI21: {
		// TODO ADRP ins
		kpdebug("RR_AARCH64_ADR_PREL_PG_HI21: val=0x%lx\n", val);
		val = (val >> 12) - ((unsigned long)loc2 >> 12);
		kpdebug("val=0x%lx\n",val);
		uint32_t immLo = (val & 0x3) << 29;
		uint32_t immHi = (val & 0x1FFFFC) << 3;
		uint64_t mask = (0x3 << 29) | (0x1FFFFC << 3);
		*(unsigned int*)loc = (*(unsigned int*)loc & ~mask) | immLo | immHi;
		//*(unsigned int*)loc &= 0x7fffffff;
		kpdebug("lo=0x%x hi=0x%x\n",immLo,immHi);
		kpdebug("R_AARCH64_ADR_PREL_PG_HI21: loc=0x%x, val=0x%lx\n", *(unsigned int *)loc, val);
		break;
	}
	default:
		kperr("unknown relocation type: %lx\n", r->r_info);
		return -1;
	}
	return 0;
}

int kpatch_arch_apply_relocate_add(struct object_file *o, GElf_Shdr *relsec)
{
	struct kpatch_file *kp = o->kpfile.patch;
	GElf_Ehdr *ehdr = (void *)kp + kp->kpatch_offset;
	GElf_Shdr *shdr = (void *)ehdr + ehdr->e_shoff, *symhdr;
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

	scnname = secname(ehdr, shdr + relsec->sh_info);
	kpdebug("applying relocations to '%s'\n", scnname);
	is_kpatch_info = strcmp(scnname, ".kpatch.info") == 0;

	for (i = 0; i < relsec->sh_size / sizeof(*relocs); i++) {
		GElf_Rela *r = relocs + i;
		GElf_Sym *s;
		unsigned long val;
		void *loc, *loc2;

		if (r->r_offset < 0 || r->r_offset >= tshdr->sh_size)
			kpfatalerror("Relocation offset for section '%s'"
				     " is at 0x%lx beyond the section size 0x%lx\n",
				     scnname, r->r_offset, tshdr->sh_size);

		/* Location in our address space */
		loc = t + r->r_offset;
		/* Location in target process address space (for relative addressing) */
		loc2 = tshdr2 + r->r_offset;
		s = (GElf_Sym *)((void *)ehdr + symhdr->sh_offset) + GELF_R_SYM(r->r_info);
		val = s->st_value + r->r_addend;

		if (is_kpatch_info && is_undef_symbol(s)) {
			val = s->st_size;
		}

		kpatch_arch_apply_relocate(r, s, loc, loc2, val);
	}

	return 0;
}


#define JMP_TABLE_JUMP  0xd61f022058000051 /*  ldr x17 #8; br x17 */
unsigned long kpatch_arch_add_jmp_entry(struct object_file *o, unsigned long addr)
{
	struct kpatch_jmp_table_entry entry = {JMP_TABLE_JUMP, addr};
	int e;

	if (o->jmp_table == NULL) {
		kpfatalerror("JMP TABLE not found\n");
		return 0;
	}

	if (o->jmp_table->cur_entry >= o->jmp_table->max_entry)
		return 0;
	e = o->jmp_table->cur_entry++;
	o->jmp_table->entries[e] = entry;
	return (unsigned long)(o->kpta + o->kpfile.patch->jmp_offset + \
			((void *)&o->jmp_table->entries[e] - (void *)o->jmp_table));
}
