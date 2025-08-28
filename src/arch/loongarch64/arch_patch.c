#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include "include/kpatch_patch.h"
#include "include/kpatch_user.h"
#include "include/kpatch_storage.h"
#include "include/kpatch_process.h"
#include "include/kpatch_file.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_ptrace.h"
#include "include/list.h"
#include "include/kpatch_log.h"
#include "loongarch64_imm.h"

/*
 * This flag is local, i.e. it is never stored to the
 * patch applied to patient's memory.
 */
unsigned int PATCH_APPLIED = (1 << 31);
unsigned int HUNK_SIZE = 4;

int patch_apply_hunk(struct object_file *o, size_t nhunk)
{
	int ret;
	struct kpatch_info *info = &o->info[nhunk];
	unsigned long pundo;

	if (is_new_func(info))
		return 0;

	if (info->daddr & 0x3) {
        kperr("unaligned patch address: 0x%lx\n", info->daddr);
        return -1;
    }
	pundo = o->kpta + o->kpfile.patch->user_undo + nhunk * HUNK_SIZE;
	kpinfo("%s origcode from 0x%lx+0x%x to 0x%lx\n",
	       o->name, info->daddr, HUNK_SIZE, pundo);
	ret = kpatch_process_memcpy(o->proc, pundo, info->daddr, HUNK_SIZE);
	if (ret < 0)
		return ret;

	kpinfo("%s hunk 0x%lx+0x%x -> 0x%lx+0x%x\n",
	       o->name, info->daddr, info->dlen, info->saddr, info->slen);
	
	int64_t byte_offset = (int64_t)(info->saddr - info->daddr);
    int64_t imm26 = byte_offset >> 2;
    if (imm26 < -(1 << 25) || imm26 >= (1 << 25) - 1) {
        kperr("branch target out of range: %ld\n", imm26);
        return -1;
    }
	
	uint32_t imm26_l16= (uint32_t)(imm26 & 0xFFFFu) ;
    uint32_t imm26_h10= (uint32_t)((imm26 >> 16) & 0x3FFu);
    uint32_t inst = 0x50000000 | (imm26_l16 << 10) | imm26_h10;
    char code[HUNK_SIZE];
	*(uint32_t *)code = inst;
	ret = kpatch_process_mem_write(o->proc,
				       code,
				       info->daddr,
				       HUNK_SIZE);
	if (ret < 0) {
		kperr("Failed to write remote info");
	}

	/*
	 * NOTE(pboldin): This is only stored locally, as information have
	 * been copied to patient's memory already.
	 */
	info->flags |= PATCH_APPLIED;
	return ret ? -1 : 0;
}
