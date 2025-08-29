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
        if (GELF_R_TYPE(rela->r_info) != R_LARCH_TLS_IE_HI20 &&
            GELF_R_TYPE(rela->r_info) != R_LARCH_TLS_IE_LO12)
            continue;

        if (ELF64_R_SYM(rela->r_info) == 0 &&
            rela->r_addend == tls_offset)
            return rela->r_offset;
    }

    kperr("cannot find GOT entry for %lx\n", tls_offset);
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

        if (GELF_R_TYPE(rela->r_info) != R_LARCH_TLS_IE_HI20 && 
            GELF_R_TYPE(rela->r_info) != R_LARCH_TLS_IE_LO12)
            continue;

        if (ELF64_R_SYM(rela->r_info) == 0)
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

int
kpatch_arch_fixup_rela_update_tls(kpatch_objinfo *origbin,
                  kpatch_objinfo *patch,
                  GElf_Rela *rela,
                  GElf_Sym *sym,
                  GElf_Shdr *sh_text,
                  unsigned char *text)
{
    const char *symname = kpatch_objinfo_strptr(patch, SYMBOL_NAME, sym->st_name);

    switch (GELF_R_TYPE(rela->r_info)) {
    case R_LARCH_TLS_LE_LO12_R:
    case R_LARCH_TLS_LE_LO12: {
        unsigned long orig_offset;
        if (kpatch_get_original_symbol_loc(origbin, symname, &orig_offset, NULL) != SECTION_OFFSET_FOUND) {
            kperr("TLS symbol %s not found in target program\n", symname);
            return -1;
        }
        if (orig_offset != sym->st_value) {
            kperr("TLS symbol %s offset not match (orig:0x%lx != patch:0x%lx)\n",
                  symname, orig_offset, sym->st_value);
            return -1;
        }
        rela->r_info = GELF_R_INFO(0, R_LARCH_NONE);
        break;
    }

    case R_LARCH_TLS_IE_PC_HI20:
    case R_LARCH_TLS_IE_PC_LO12:
    case R_LARCH_TLS_IE_HI20:
    case R_LARCH_TLS_IE_LO12:
        return update_reloc_with_tls_got_entry(origbin, patch, rela, sym);

    default:
        kperr("Unsupported TLS relocation type: %lu\n", GELF_R_TYPE(rela->r_info));
        return -1;
    }
    return 0;
}

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

    	if (j == orig->nsym) {
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
