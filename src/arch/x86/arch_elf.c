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
