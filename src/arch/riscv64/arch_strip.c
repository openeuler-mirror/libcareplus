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
        /* This symbol should have a TLS_TPRELnn entry in the GOT with
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
        kpinfo("Changing TLS_GOT_HI20 symbol %s from %lx to %lx\n",
               symname, rela->r_addend, got_offset);
        rela->r_addend = got_offset;
    }
    return 0;
}

/* please see x86 comment */
int
kpatch_arch_fixup_rela_update_tls(kpatch_objinfo *origbin,
                  kpatch_objinfo *patch,
                  GElf_Rela *rela,
                  GElf_Sym *sym,
                  GElf_Shdr *sh_text,
                  unsigned char *text)
{
    switch (GELF_R_TYPE(rela->r_info)) {
    case R_RISCV_TPREL_HI20:        // local exec
    case R_RISCV_TPREL_ADD:
    case R_RISCV_TPREL_LO12_I:
    case R_RISCV_TPREL_LO12_S:
    case R_RISCV_TPREL_I:   // psABI 1.0-rc4 marked as reserved
    case R_RISCV_TPREL_S:   // psABI 1.0-rc4 marked as reserved
        return 0;
    case R_RISCV_TLS_GOT_HI20:      // initial exec
        return update_reloc_with_tls_got_entry(origbin, patch, rela, sym);

    default:
        kperr("non-supported TLS relocation type: %ld\n",
                                GELF_R_TYPE(rela->r_info));
        return -1;
    }

    return 0;
}

/*
 * Patch might import new library global variables, such as stderr.
 * Normally, they are marked as R_RISCV_COPY in .rela.dyn section, and
 * copied to .bss segment when loading, and their symbols are marked
 * as defined.
 *
 * Because .rela.dyn has been stripped out, we hook at kpatch_strip.c
 * to find them and remark the symbol as undefined, so kpatch_elf.c
 * can take care of them using jump table.
 */
int
kpatch_arch_fixup_rela_copy(kpatch_objinfo *origbin, GElf_Sym *s,
		                    const char *symname)
{
    if (strchr(symname, '@') &&
            !kpatch_objinfo_find_scn_by_name(origbin, symname, NULL)) {
        s->st_shndx = SHN_UNDEF;
        return 1;
    }
    return 0;
}

/*
 * Patch records original functions section-relative offset. But due to
 * static linker relax behavior, the records might be different with the
 * original's.
 * An example is new_var test. When compiled, linker linked a C library
 * function `__do_global_dtors_aux` in .text section, which has an
 * "auipc; addi" code sequence with R_RISCV_RELAX relocation. For original,
 * they were relaxed as a single "addi". But for patch, they were not
 * relaxed. Thus patch recorded offset is 4 bytes bias against the
 * original.
 * I tried to arrange patch memory layout all behind .bss section,
 * but nothing helped. Here we try verify and overcome this problem.
 */
int
kpatch_arch_fixup_addr_bias(kpatch_objinfo *orig, kpatch_objinfo *patch)
{
	GElf_Sym sorig, spat;
    GElf_Shdr shdr;
    const char *name, *tmp;
	size_t i, j;

	for (i = 1; i < patch->nsym; i++) {
		if (!gelf_getsym(patch->symtab, i, &spat)) {
			kperr("Failed to do gelf_getsym");
			return -1;
		}
		if ((spat.st_shndx == SHN_UNDEF) ||
                    (GELF_ST_TYPE(spat.st_info) != STT_FUNC))
			continue;
        if (kpatch_objinfo_getshdr(patch, spat.st_shndx, &shdr) == NULL)
            return -1;
        name = kpatch_objinfo_strptr(patch, SECTION_NAME, shdr.sh_name);
        if (!strncmp(name, ".kpatch.", 8))
            continue;

        name = kpatch_objinfo_strptr(patch, SYMBOL_NAME, spat.st_name);
	    for (j = 1; j < orig->nsym; j++) {
    		if (!gelf_getsym(orig->symtab, j, &sorig)) {
	    		kperr("Failed to do gelf_getsym origbin\n");
		    	return -1;
		    }
		    tmp = kpatch_objinfo_strptr(orig, SYMBOL_NAME, sorig.st_name);
    		if (!strcmp(tmp, name) && (sorig.st_info == spat.st_info)) {
                if (!kpatch_objinfo_getshdr(orig, sorig.st_shndx, &shdr))
                    return -1;
		    	break;
		    }
	    }

    	if (j == orig->nsym) {// test fail_threading .st_name are all 0, why???
            kperr("Not found '%s' in original\n", name);
            continue;
        }

        if (spat.st_value != sorig.st_value - shdr.sh_addr) {
            kpwarn("Fixed %ld bytes address bias of original symbol %s\n",
                    spat.st_value + shdr.sh_addr - sorig.st_value, name);
            spat.st_value = sorig.st_value - shdr.sh_addr;
            gelf_update_sym(patch->symtab, i, &spat);
        }
    }
    return 0;
}