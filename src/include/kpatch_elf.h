#ifndef __KPATCH_ELF__
#define __KPATCH_ELF__
#include <gelf.h>
#include "kpatch_process.h"

const char *kpatch_get_buildid(struct object_file *o);

/*
 * Set ELF header (and program headers if they fit)
 * from the already read `buf` of size `bufsize`.
 */
int
kpatch_elf_object_set_ehdr(struct object_file *o,
			   const unsigned char *buf,
			   size_t bufsize);

int kpatch_elf_object_is_shared_lib(struct object_file *o);
int kpatch_elf_parse_program_header(struct object_file *o);
int kpatch_elf_load_kpatch_info(struct object_file *o);
void kpatch_get_kpatch_data_offset(struct object_file *o);

int kpatch_resolve(struct object_file *o);
int kpatch_relocate(struct object_file *o);

struct kpatch_jmp_table *kpatch_new_jmp_table(int entries);
int kpatch_count_undefined(struct object_file *o);

int kpatch_resolve_undefined_single_dynamic(struct object_file *o,
					    const char *sname,
					    unsigned long *addr);

unsigned long vaddr2addr(struct object_file *o, unsigned long vaddr);

struct kpatch_jmp_table_entry {
	unsigned long jmp;
#ifdef __riscv
	/* at least 3 instructions for arbitrary +-2G access */
	unsigned long jmp1;
#elif defined (__loongarch64)
	unsigned long jmp1;
#endif
	unsigned long addr;
};

struct kpatch_jmp_table {
	unsigned int size;
	unsigned int cur_entry;
	unsigned int max_entry;

	struct kpatch_jmp_table_entry entries[0];
};

unsigned long kpatch_arch_add_jmp_entry(struct object_file *o, unsigned long addr);

char *secname(GElf_Ehdr *ehdr, GElf_Shdr *s);
int is_undef_symbol(const Elf64_Sym *sym);
int kpatch_arch_apply_relocate_add(struct object_file *o, GElf_Shdr *relsec);

#endif
