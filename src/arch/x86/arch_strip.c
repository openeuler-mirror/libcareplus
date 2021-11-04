/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Description: add support for x86 architecture TLS symbol with IE model.
 ******************************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "include/kpatch_file.h"
#include "include/kpatch_common.h"

#include <gelf.h>
#include "include/kpatch_elf_objinfo.h"

#include "include/kpatch_log.h"
#include "include/kpatch_strip.h"

#define SECTION_OFFSET_FOUND        0x0
#define SECTION_NOT_FOUND       0x1

/* Update relocation against TLS symbol.
 *
 * Thread-Local Storage variables require special care because they are
 * referenced by the offset into Thread Local Storage allocated for each
 * thread. There are different models for TLS and we only support Initial-Exec.
 *
 * The following types of relocations are handled:
 *
 * - Relocs of type TPOFF32 targeting symbols in the original are changed
 *   to reloc type NONE after the symbol is checked to be present at the
 *   same place in the original binary. (TODO)
 *
 *   *NOTE* the only way to support new variables allocated by patch is to use
 *   dlopen-loaded patches.
 * - Relocs of type TPOFF64 are ignored. These are only used for long memory
 *   model or as entries to GOT.
 * - Relocs of type GOTTPOFF are quite tricky. These usually point to a GOT
 *   entry filled with TPOFF64 relocation. We can't do this relocation on our
 *   own because it requires digging into glibc internels with a hack.
 *
 *   Instead, we cheat here and find the appropriate TPOFF64 relocations IN
 *   THE ORIGINAL object and make GOTTPOFF point there. This is different for
 *   local/global symbols but is not very hard.
 *
 * Returns 1 when symbol must be updated, 0 when everything is OK, -1 on error.
 */
int
kpatch_arch_fixup_rela_update_tls(kpatch_objinfo *origbin,
			     kpatch_objinfo *patch,
			     GElf_Rela *rela,
			     GElf_Sym *sym,
			     GElf_Shdr *sh_text,
			     unsigned char *text)
{
	switch (GELF_R_TYPE(rela->r_info)) {
	case R_X86_64_GOTTPOFF:
	case R_X86_64_TPOFF32: {
		const char *symname;
		int rv;
		unsigned long off;
		/* Leave the value as is, just check offset is the same. */
		rela->r_info = GELF_R_INFO(0, R_X86_64_NONE);
		symname = kpatch_objinfo_strptr(patch, SYMBOL_NAME,
						sym->st_name);

		rv = kpatch_get_original_symbol_loc(
			origbin, symname, &off, NULL);
		if (rv == SECTION_NOT_FOUND) {
			kpfatalerror(
				"TLS symbol %s not found in original binary",
				symname);
		}

	    kpinfo("Compare TLS symbol %s offset: %lx in origbinal binary, %lx in patch\n",
				symname, off, sym->st_value);
        if (off != sym->st_value) {
                kpfatalerror("TLS symbol %s has different offset!\n", symname);
        }

		return 0;
	}

	case R_X86_64_DTPOFF32:
	case R_X86_64_DTPOFF64:
	case R_X86_64_DTPMOD64:
	case R_X86_64_TLSGD:
	case R_X86_64_TLSLD:
	case R_X86_64_TPOFF64:
	default:
		kpfatalerror("non-supported TLS model\n");
		return -1;
	}

	return 0;
}
