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
 * Description: add support for aarch64 architecture TLS symbol with IE model.
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


/* Update relocation against TLS symbol.
 *
 * Thread-Local Storage variables require special care because they are
 * referenced by the offset into Thread Local Storage allocated for each
 * thread. There are different models for TLS and we only support Initial-Exec.
 *
 * Returns 1 when symbol must be updated, 0 when everything is OK, -1 on error.
 */

#define MASK(n) ((1u << (n)) - 1)

static uint32_t objinfo_find_tls_got_by_offset(GElf_Rela *rel,
						GElf_Shdr *sh_text,
						unsigned char *text)
{
	int i;
	unsigned long off;
	uint32_t insn;
	uint32_t imm;
	uint32_t gotoffset;

	off = rel->r_offset - sh_text->sh_addr;

	/* Get ins from text according to ARM ABI */
	insn = (unsigned long)text[off];
	for (i = 1; i <= 3; i++) {
		insn = insn + ((unsigned long)text[off + i] << (8 * i));
	}

	imm = (((insn >> 5) & MASK (19)) << 2) | ((insn >> 29) & MASK (2));
	imm = imm << 12;

	gotoffset = imm + (sh_text->sh_addr & 0xfffff000);

	return gotoffset;
}

int
kpatch_arch_fixup_rela_update_tls(kpatch_objinfo *origbin,
			     kpatch_objinfo *patch,
			     GElf_Rela *rela,
			     GElf_Sym *sym,
			     GElf_Shdr *sh_text,
			     unsigned char *text)
{
	unsigned long got_offset;

	char *symname, *tmp;

	/* Do nothing for Local TLS symbol */
	if (GELF_ST_BIND(sym->st_info) != STB_LOCAL)
		return 0;

	symname = (char *)kpatch_objinfo_strptr(patch,
					SYMBOL_NAME, sym->st_name);
	tmp = strchr(symname, '@');
	if (tmp != NULL)
		*tmp = '\0';

	switch (GELF_R_TYPE(rela->r_info)) {
	case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
		got_offset = objinfo_find_tls_got_by_offset(rela, sh_text, text);
		kpinfo("Fix relocation for TLS symbol %s from %lx to %lx\n",
			symname, rela->r_addend, got_offset);
		rela->r_addend = got_offset;
		break;
	case R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
		break;
	default:
		kperr("non-supported TLS model\n");
		return -1;
	}

	return 0;
}

int
kpatch_arch_fixup_rela_copy(kpatch_objinfo *origbin, GElf_Sym *s,
		                    const char *symname)
{
	return 0;
}

int
kpatch_arch_fixup_addr_bias(kpatch_objinfo *orig, kpatch_objinfo *patch)
{
	return 0;
}
