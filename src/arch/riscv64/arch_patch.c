/******************************************************************************
 * 2021.10.08 - ptrace/process/patch: fix some bad code problem
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 ******************************************************************************/

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
#include "riscv64_imm.h"

/*
 * This flag is local, i.e. it is never stored to the
 * patch applied to patient's memory.
 */
unsigned int PATCH_APPLIED = (1 << 31);
unsigned int HUNK_SIZE = 8; // 2 instructions

int patch_apply_hunk(struct object_file *o, size_t nhunk)
{
    int ret;
    unsigned code[2];
    struct kpatch_info *info = &o->info[nhunk];
    unsigned long pundo;

    if (is_new_func(info))
        return 0;

    pundo = o->kpta + o->kpfile.patch->user_undo + nhunk * HUNK_SIZE;
    kpinfo("%s origcode from 0x%lx+0x%x to 0x%lx\n",
           o->name, info->daddr, HUNK_SIZE, pundo);
    ret = kpatch_process_memcpy(o->proc, pundo, info->daddr, HUNK_SIZE);
    if (ret < 0)
        return ret;

    kpinfo("%s hunk 0x%lx+0x%x -> 0x%lx+0x%x\n",
           o->name, info->daddr, info->dlen, info->saddr, info->slen);

    int offset = info->saddr - info->daddr;
    code[0] = set_utype_imm(0xf97, offset);     // auipc t6 offset
    code[1] = set_itype_imm(0xf8067, offset);   // jr t6

    ret = kpatch_process_mem_write(o->proc, code, info->daddr, sizeof(code));
    if (ret < 0) {
        kperr("Failed to write remote info\n");
    }
    /*
     * NOTE(pboldin): This is only stored locally, as information have
     * been copied to patient's memory already.
     */
    info->flags |= PATCH_APPLIED;
    return ret ? -1 : 0;
}
