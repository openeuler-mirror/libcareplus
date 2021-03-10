/******************************************************************************
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

#include "include/kpatch_common.h"
#include "include/kpatch_user.h"
#include "include/kpatch_process.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_file.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"

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

		if (r->r_offset < 0 || r->r_offset >= tshdr->sh_size) {
			kpfatalerror("Relocation offset for section '%s'"
				     " is at 0x%lx beyond the section size 0x%lx\n",
				     scnname, r->r_offset, tshdr->sh_size);
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

		switch (GELF_R_TYPE(r->r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			*(unsigned long *)loc = val;
			break;
		case R_X86_64_32:
			*(unsigned int *)loc = val;
			break;
		case R_X86_64_32S:
			*(signed int *)loc = val;
			break;
		case R_X86_64_GOTTPOFF:
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
			if (is_undef_symbol(s)) {
				/* This is an undefined symbol,
				 * use jmp table as the GOT */
				val += sizeof(unsigned long);
			} else if (GELF_ST_TYPE(s->st_info) == STT_TLS) {
				/* This is GOTTPOFF that already points
				 * to an appropriate GOT entry in the
				 * patient's memory.
				 */
				val = r->r_addend + o->load_offset - 4;
			}
			/* FALLTHROUGH */
		case R_X86_64_PC32:
			val -= (unsigned long)loc2;
			*(unsigned int *)loc = val;
			break;
		case R_X86_64_TPOFF64:
		case R_X86_64_TPOFF32:
			kperr("TPOFF32/TPOFF64 should not be present\n");
			break;
		default:
			kperr("unknown relocation type: %lx\n", r->r_info);
			return -1;
		}
	}

	return 0;
}


#define JMP_TABLE_JUMP  0x90900000000225ff /* jmp [rip+2]; nop; nop */
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
