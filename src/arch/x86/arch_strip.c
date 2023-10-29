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

/* Find Global Offset Table entry with the address of the TLS-variable
 * specified by the `tls_offset`. Dynamic linker allocates Thread-Local storage
 * as described in ABI and places the correct offset at that address in GOT. We
 * then read this offset and use it in our jmp table.
 */
static unsigned long
objinfo_find_tls_got_by_offset(kpatch_objinfo *oi,
			       unsigned long tls_offset)
{
	Elf64_Rela *rela;
	size_t nrela;

	if (kpatch_objinfo_load_tls_reladyn(oi) < 0)
		kpfatalerror("kpatch_objinfo_load_tls_reladyn");

	rela = oi->tlsreladyn;
	nrela = oi->ntlsreladyn;

	for (; nrela != 0; rela++, nrela--) {
		if (!kpatch_is_tls_rela(rela))
			continue;

		if (ELF64_R_SYM(rela->r_info) == 0 &&
		    rela->r_addend == tls_offset)
			return rela->r_offset;
	}

	kpfatalerror("cannot find GOT entry for %lx\n", tls_offset);
	return 0;
}

static unsigned long
objinfo_find_tls_got_by_symname(kpatch_objinfo *oi,
				const char *symname)
{
	Elf64_Rela *rela;
	size_t nrela;
	Elf64_Sym sym;

	if (kpatch_objinfo_load_tls_reladyn(oi) < 0)
	    kpfatalerror("kpatch_objinfo_load_tls_reladyn");

	rela = oi->tlsreladyn;
	nrela = oi->ntlsreladyn;

	for (; nrela != 0; rela++, nrela--) {
		const char *origname;

		if (!kpatch_is_tls_rela(rela))
			continue;

		if (ELF64_R_SYM(rela->r_info) == 0 ||
				rela->r_addend != 0)
			continue;

		if (!gelf_getsym(oi->dynsymtab, ELF64_R_SYM(rela->r_info), &sym))
			kpfatalerror("gelf_getsym");

		origname = kpatch_objinfo_strptr(oi, DYNAMIC_NAME,
						 sym.st_name);

		if (strcmp(origname, symname) == 0 &&
		    rela->r_addend == 0)
			return rela->r_offset;
	}

	kpfatalerror("cannot find GOT entry for %s\n", symname);
	return 0;
}

static inline int
update_reloc_with_tls_got_entry(kpatch_objinfo *origbin,
				kpatch_objinfo *patch,
				GElf_Rela *rela,
				GElf_Sym *sym)
{
	unsigned long got_offset;
	char *symname, *tmp;

	symname = (char *)kpatch_objinfo_strptr(patch, SYMBOL_NAME, sym->st_name);

	tmp = strchr(symname, '@');
	if (tmp != NULL) {
		*tmp = '\0';
	}

	if (GELF_ST_BIND(sym->st_info) == STB_LOCAL ||
	    sym->st_shndx != SHN_UNDEF) {
	    /* This symbol should have a TPOFF64 entry in the GOT with
	     * the offset of sym->st_value.  Find GOT entry for this TLS
	     * variable. Make st_value point to that GOT entry and mark it
	     * with flag.
	     */

		got_offset = objinfo_find_tls_got_by_offset(origbin, sym->st_value);
	} else if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL &&
		   sym->st_shndx == SHN_UNDEF) {
		   /* This is a GLOBAL symbol we require from some other binary.
		    * It has a GOT entry that is referenced by the symbol name,
		    * not the offset.
		    */

		got_offset = objinfo_find_tls_got_by_symname(origbin, symname);
	} else {
		kperr("get symbol '%s' got_offset failed\n", symname);
		return -1;
	}

	if (rela->r_addend != got_offset) {
		kpinfo("Changing GOTTPOFF symbol %s from %lx to %lx\n",
		       symname, rela->r_addend, got_offset);
		rela->r_addend = got_offset;
	}
	return 0;
}

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
			kperr("TLS symbol %s not found in original binary", symname);
			return -1;
		}

	    kpinfo("Compare TLS symbol %s offset: %lx in origbinal binary, %lx in patch\n",
				symname, off, sym->st_value);
        if (off != sym->st_value) {
                kperr("TLS symbol %s has different offset!\n", symname);
		return -1;
        }

		return 0;
	}

	case R_X86_64_GOTTPOFF:
		return update_reloc_with_tls_got_entry(origbin, patch, rela, sym);

	case R_X86_64_DTPOFF32:
	case R_X86_64_DTPOFF64:
	case R_X86_64_DTPMOD64:
	case R_X86_64_TLSGD:
	case R_X86_64_TLSLD:
	case R_X86_64_TPOFF64:
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
