/******************************************************************************
 * 2021.10.08 - storage/strip: fix some bad code problem
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 *
 * 2021.10.08 - remove deprecated code
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.09.23 - tls: add support for tls symbol
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
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

#define ALIGN(off,sz) (((off)+(sz)-1)&~((sz)-1))

#define MODE_STRIP 1
#define MODE_LIST 2
#define MODE_FIXUP 3
#define MODE_REL_FIXUP 4
#define MODE_UNDO_LINK 5

int need_section(const char *name)
{
	if (strstr(name, "kpatch"))
		return 1;
	if (!strcmp(name, ".symtab"))
		return 1;
	if (!strcmp(name, ".strtab"))
		return 1;
	if (!strcmp(name, ".shstrtab"))
		return 1;
	return 0;
}

Elf *kpatch_open_elf(const char *file, int create)
{
	int fd;
	Elf *elf;

	fd = open(file, O_RDWR | (create ? O_CREAT : 0), 0660);
	if (fd == -1)
		kpfatalerror("open");
	elf = elf_begin(fd, (create ? ELF_C_WRITE : ELF_C_RDWR), NULL);
	close(fd);
	if (!elf)
		kpfatalerror("elf_begin");

	return elf;
}

static int check_info_len(struct kpatch_info *info, size_t scnsize)
{
	int ret = 0, i = 0;

        for (; i<scnsize; i++) {
	        if (is_new_func(&info[i]))
	 	       continue;

		if (info[i].dlen < 5) {
			kperr("too small function to patch at 0x%lx\n",
			      info[i].daddr);
			ret = 1;
		}

	}
	return ret;
}

#define KPATCH_INFO_LAST_SIZE	24

static size_t process_kpatch_info(Elf_Scn *scnout, GElf_Shdr *hdr)
{
	Elf_Data *prev = elf_getdata(scnout, NULL);
	Elf_Data *data = elf_newdata(scnout);
	static char info_term[KPATCH_INFO_LAST_SIZE];

	if (!prev)
		kpfatalerror("elf_getdata/info");
	if (!data)
		kpfatalerror("elf_newdata/info");

	if(check_info_len((void*)prev->d_buf, prev->d_size/sizeof(struct kpatch_info)))
                kpfatalerror("functions_too_small_to_patch");
	data->d_align = 1;
	data->d_buf = info_term;
	data->d_off = prev->d_size;
	data->d_size = KPATCH_INFO_LAST_SIZE;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	hdr->sh_size += KPATCH_INFO_LAST_SIZE;

	return KPATCH_INFO_LAST_SIZE;
}

static int kpatch_strip(Elf *elfin, Elf *elfout)
{
	GElf_Ehdr ehin, ehout;
	Elf_Scn *scnin = NULL, *scnout = NULL;
	Elf_Data *dataout;
	GElf_Shdr shin, shout;
	Elf64_Off off = -1ull;
	size_t shstridx;
	char *scnname;

	if (!gelf_newehdr(elfout, gelf_getclass(elfin)))
		kpfatalerror("gelf_newhdr");
	if (!gelf_getehdr(elfout, &ehout))
		kpfatalerror("gelf_getehdr out");
	if (!gelf_getehdr(elfin, &ehin))
		kpfatalerror("gelf_getehdr in");

	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = ehin.e_ident[EI_DATA];
	ehout.e_machine = ehin.e_machine;
	ehout.e_type = ehin.e_type;
	ehout.e_version = ehin.e_version;
	ehout.e_shstrndx = ehin.e_shstrndx;
	ehout.e_shentsize = ehin.e_shentsize;
	ehout.e_phoff = 0;

	if (_elf_getshdrstrndx(elfin, &shstridx))
		kpfatalerror("elf_getshdrstrndx");
	while ((scnin = elf_nextscn(elfin, scnin)) != NULL) {
		scnout = elf_newscn(elfout);
		if (!scnout)
			kpfatalerror("elf_newscn");
		if (!gelf_getshdr(scnout, &shout))
			kpfatalerror("gelf_getshdr out");
		if (!gelf_getshdr(scnin, &shin))
			kpfatalerror("gelf_getshdr in");
		scnname = elf_strptr(elfin, shstridx, shin.sh_name);
		if (!scnname) {
			kpfatalerror("elf_strptr");
		}
		shout = shin;

		if (off != -1ull) {
			off = ALIGN(off, shout.sh_addralign);
			shout.sh_offset = off;
		} else
			off = shin.sh_offset;

		kpinfo("processing '%s'...", scnname);
		if (need_section(scnname)) {
			kpinfo("need it\n");
			dataout = elf_newdata(scnout);
			if (!dataout)
				kpfatalerror("elf_newdata");
			*dataout = *elf_getdata(scnin, NULL);
			off += shin.sh_size;
			if (!strcmp(scnname, ".kpatch.info"))
				off += process_kpatch_info(scnout, &shout);
		} else {
			kpinfo("don't need it\n");
			shout.sh_type = SHT_NOBITS;
		}
		if (!gelf_update_shdr(scnout, &shout))
			kpfatalerror("gelf_update_shdr need");
		if (!elf_flagscn(scnout, ELF_C_SET, ELF_F_DIRTY))
			kpfatalerror("elf_flagscn");
	}

	if (off == -1ull) {
		kpfatalerror("off is equal to -1");
	}

	off = ALIGN(off, 8);
	ehout.e_shoff = off;

	if (!gelf_update_ehdr(elfout, &ehout))
		kpfatalerror("gelf_update_ehdr");
	if (!elf_flagelf(elfout, ELF_C_SET, ELF_F_LAYOUT))
		kpfatalerror("elf_flagelf");
	if (elf_update(elfout, ELF_C_WRITE) < 0)
		kpfatalerror("elf_update");
	if (elf_end(elfout))
		kpfatalerror("elf_end");
	return 0;
}

#define SECTION_OFFSET_FOUND		0x0
#define SECTION_NOT_FOUND		0x1

static int
kpatch_get_symbol_offset_rel_section(kpatch_objinfo *oi,
				     GElf_Sym *sym,
				     size_t *symoff,
				     const char **secname)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	const char *t;

	if (GELF_ST_TYPE(sym->st_info) == STT_TLS) {
		*symoff = sym->st_value;
		if (secname != NULL)
			*secname = NULL;
		return 0;
	}

	if (!(scn = elf_getscn(oi->elf, sym->st_shndx)))
		kpfatalerror("elf_getscn origbin");
	if (!gelf_getshdr(scn, &shdr))
		kpfatalerror("gelf_getshdr origbin");

	if (shdr.sh_addr > sym->st_value)
		kpfatalerror("TODO: shared libraries???\n");

	*symoff = sym->st_value - shdr.sh_addr;
	t = kpatch_objinfo_strptr(oi, SECTION_NAME, shdr.sh_name);
	if (t == NULL)
		return -1;

	*secname = t;

	return 0;
}

int
kpatch_get_original_symbol_loc(kpatch_objinfo *origbin,
			       const char *symname,
			       size_t *symoff,
			       const char **secname)
{
	GElf_Sym *sym = NULL, s;
	size_t i;
	const char *tmp;

	if (kpatch_objinfo_load(origbin) < 0)
		kpfatalerror("kpatch_load_object_info");

	for (i = 0; i < origbin->nsym; i++) {
		if (!gelf_getsym(origbin->symtab, i, &s))
			kpfatalerror("gelf_getsym origbin\n");
		tmp = kpatch_objinfo_strptr(origbin, SYMBOL_NAME, s.st_name);
		if (tmp != NULL && !strcmp(tmp, symname)) {
			sym = &s;
			break;
		}
	}
	if (sym == NULL || sym->st_shndx == 0)
		return SECTION_NOT_FOUND;

	if (kpatch_get_symbol_offset_rel_section(origbin, sym, symoff, secname) == 0)
		return SECTION_OFFSET_FOUND;

	return -1;
}

static int
kpatch_get_local_symbol_loc(kpatch_objinfo *oi,
			    GElf_Sym *sym,
			    size_t *symoff,
			    const char **secname,
			    size_t *section_symn)
{
	GElf_Sym sectionsym;
	size_t i;

	for (i = 0; i < oi->nsym; i++) {
		if (!gelf_getsym(oi->symtab, i, &sectionsym))
			kpfatalerror("gelf_getsym\n");
		if (GELF_ST_TYPE(sectionsym.st_info) != STT_SECTION)
			continue;
		if (sectionsym.st_shndx == sym->st_shndx)
			break;
	}
	if (i == oi->nsym)
		return SECTION_NOT_FOUND;

	if (kpatch_get_symbol_offset_rel_section(oi, sym, symoff, secname))
		return -1;

	*section_symn = i;
	return SECTION_OFFSET_FOUND;
}

/* Redos one relocation with addend against symbol into relocation against
 * section.
 *
 * Usually, there are no symbols in the binary except for dynamically exported.
 * So, we convert all the relocations against a symbol into the relocations
 * against the section. (TODO we should actually stop doing it).
 *
 * The following is an algorithm of how it is done:
 * - PLT32 relocations are changed to PC32.
 * - Relocs against symbols in the .kpatch sections are left as is.
 * - Relocs against local symbols (GELF_ST_BIND(st_info) == STB_LOCAL)
 *   are redone iff the name starts with '.' as relocations against the
 *   appropriate sections.
 * - Relocs against global symbols (STB_GLOBAL) imported from some library
 *   are left as is. The patcher will see st_shndx == SHN_UNDEF and resolve
 *   these.
 * - Relocs against TLS symbols are done by the `kpatch_fixup_rela_update_tls`.
 *   Take a look at the comment.
 *
 * Return 1 if symbol was updated, 0 if not and -1 on error
 */
static inline int
kpatch_fixup_rela_one(kpatch_objinfo *origbin,
		      kpatch_objinfo *patch,
		      GElf_Rela *rel,
		      GElf_Sym *sym,
		      GElf_Shdr *sh_text,
		      unsigned char *text)
{
	const char *secname = NULL, *symname = NULL;
	int status, rv = 0;
	size_t offset, section_symn = 0;

	if (GELF_ST_TYPE(sym->st_info) == STT_SECTION) {
		/* Already OK */
		return 0;
	}

	if (GELF_ST_TYPE(sym->st_info) == STT_TLS) {
		rv = kpatch_arch_fixup_rela_update_tls(origbin, patch, rel,
							sym, sh_text, text);
		if (rv < 0)
			kpfatalerror("kpatch_fixup_rela_update_tls");

		return rv;
	}

	/*
	 * Relocations against symbols from .kpatch* sections are Ok
	 * We'll have info about them at runtime
	 */
	if (kpatch_objinfo_is_our_section(patch, sym->st_shndx))
		goto plt32_to_pc32;

	symname = kpatch_objinfo_strptr(patch, SYMBOL_NAME, sym->st_name);

	if (GELF_ST_TYPE(sym->st_info) != STT_NOTYPE &&
	    GELF_ST_TYPE(sym->st_info) != STT_FUNC &&
	    GELF_ST_TYPE(sym->st_info) != STT_OBJECT &&
	    GELF_ST_BIND(sym->st_info) != STB_LOCAL) {
		kperr("Unknown symtype for symbol %s: %x\n", symname,
		      GELF_ST_TYPE(sym->st_info));
		return -1;
	}

	kpinfo("Fixing up relocation %s+%lx\n", symname, rel->r_addend);
	if (GELF_ST_BIND(sym->st_info) == STB_LOCAL &&
	    symname[0] == '.') {
		/* Symbols such as .LC<d> are kept in -O2 output due to
		 * .rodata being split into str1.* subsections.
		 * Recalculate these at the appropriate sections offset */
		status = kpatch_get_local_symbol_loc(patch,
			sym, &offset, &secname, &section_symn);

		if (status == SECTION_NOT_FOUND)
			kpfatalerror("unable to find local sym's section");

		rel->r_info = GELF_R_INFO(
			section_symn,
			GELF_R_TYPE(rel->r_info));
		rel->r_addend = rel->r_addend + offset;
	}

	/* We always map patch closer than 2GiB to original so we don't need to
	 * reference known symbols via Global Offset Table. Change this:
	 *
	 *	mov	symbol@GOTPCREL(%rip), %reg
	 *	mov	(%reg), %reg
	 *
	 * to
	 *
	 *	lea	symbol@GOTPCREL(%rip), %reg
	 *	mov	(%reg), %reg
	 *
	 */
#define	MOV_INSN	0x8b
#define	LEA_INSN	0x8d

	if (sym->st_shndx != SHN_UNDEF) {
		unsigned long off;
		switch (GELF_R_TYPE(rel->r_info)) {
		case R_X86_64_GOTPCREL:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
		        off = rel->r_offset - sh_text->sh_addr - 2;

			if (text[off] == MOV_INSN) {
				//kpdebug("changing mov to lea at %lx\n", off);
				kpinfo("changing mov to lea at %lx\n", off);
				text[off] = LEA_INSN;
			}


			break;
		}
	}

	if (secname) {
		kpinfo("Relocating to %s+%lx\n", secname, rel->r_addend);
	}

plt32_to_pc32:
	if (rv >= 0 && GELF_R_TYPE(rel->r_info) == R_X86_64_PLT32)
		rel->r_info = GELF_R_INFO(
			GELF_R_SYM(rel->r_info), R_X86_64_PC32);
	return rv;
}

static int
kpatch_fixup_rela(kpatch_objinfo *origbin,
		  kpatch_objinfo *patch,
		  Elf_Scn *scn_rel,
		  GElf_Shdr *sh_rel)
{
	int rv;
	size_t i, nrel;
	Elf_Data *relatab;
	Elf_Data *symtab = patch->symtab;

	Elf_Scn *scn_text;
	Elf_Data *data_text;
	GElf_Shdr sh_text;

	nrel = sh_rel->sh_size / sh_rel->sh_entsize;
	relatab = elf_getdata(scn_rel, NULL);
	if (relatab == NULL)
		kpfatalerror("elf_getdata(relatab)");

	scn_text = kpatch_objinfo_getshdr(patch, sh_rel->sh_info, &sh_text);
	if (scn_text == NULL)
		kpfatalerror("kpatch_objinfo_getshdr(scn_text)");

	data_text = elf_getdata(scn_text, NULL);
	if (data_text == NULL)
		kpfatalerror("data_text == NULL");

	for (i = 0; i < nrel; i++) {
		GElf_Rela rel;
		GElf_Sym sym;

		if (!gelf_getrela(relatab, i, &rel))
			kpfatalerror("gelf_getrela");

		if (!gelf_getsym(symtab, GELF_R_SYM(rel.r_info), &sym))
			kpfatalerror("gelf_getsym");

		rv = kpatch_fixup_rela_one(origbin, patch, &rel, &sym,
					   &sh_text, data_text->d_buf);

		if (rv < 0)
			return rv;

		if (!gelf_update_rela(relatab, i, &rel))
			kpfatalerror("gelf_update_rela");

		if (rv &&
		    !gelf_update_sym(symtab, GELF_R_SYM(rel.r_info), &sym))
			kpfatalerror("gelf_update_sym");
	}

	elf_flagdata(data_text, ELF_C_SET, ELF_F_DIRTY);

	return 0;
}

static int kpatch_rel_fixup(Elf *elf_origbin, Elf *elf_patch)
{
	Elf_Scn *scn_patch = NULL;
	GElf_Shdr sh_patch;
	int i;
	kpatch_objinfo origbin = OBJINFO_INIT(elf_origbin);
	kpatch_objinfo patch = OBJINFO_INIT(elf_patch);


	if (kpatch_objinfo_load(&origbin))
		kpfatalerror("kpatch_load_object_info");
	if (kpatch_objinfo_load(&patch))
		kpfatalerror("kpatch_load_object_info");

	/*
	 * We redo relocations that are made against local machine-generated
	 * symbols such as .LC0 to relocations against sections.
	 *
	 * We check that symbol values are the same for human-named symbols in
	 * both the original and patch and retain the symbols and references to
	 * them to aid debugging.
	 *
	 * See comment on kpatch_fixup_rela for details.
	 */
	for (i = 1; i < patch.shnum; i++) {
		scn_patch = kpatch_objinfo_getshdr(&patch, i, &sh_patch);

		if (sh_patch.sh_type == SHT_RELA)
			if (kpatch_fixup_rela(&origbin, &patch, scn_patch, &sh_patch))
				kpfatalerror("kpatch_fixup_rela");

		if (sh_patch.sh_type == SHT_REL)
			kpfatalerror("TODO: handle SHT_REL\n");

		/* We had to update section headers otherwise updating a symbol
		   causes libelf to erase them completely, possibly a bug */
		if (!gelf_update_shdr(scn_patch, &sh_patch))
			kpfatalerror("gelf_update_shdr");
	}

	if (!elf_flagelf(elf_patch, ELF_C_SET, ELF_F_LAYOUT))
		kpfatalerror("elf_flagelf");
	if (elf_update(elf_patch, ELF_C_WRITE) < 0)
		kpfatalerror("elf_update");
	if (elf_end(elf_patch))
		kpfatalerror("elf_end");
	return 0;
}

/* Undo relocation offsets r_offset from absolute binary offset
 * to offset relative against section.
 */
static int
kpatch_rel_offset_to_relative(kpatch_objinfo *patch,
			      Elf_Scn *scn_rel,
			      GElf_Shdr *sh_rel)
{
	size_t nrel = sh_rel->sh_size / sh_rel->sh_entsize;
	Elf_Data *data = elf_getdata(scn_rel, NULL);
	GElf_Shdr sh_patch;
	int i;

	kpatch_objinfo_getshdr(patch, sh_rel->sh_info,
			       &sh_patch);

	if (sh_patch.sh_addr == 0)
		return 1;

	for (i = 0; i < nrel; i++) {
		GElf_Rela rel;

		if (!gelf_getrela(data, i, &rel))
			kpfatalerror("gelf_getrela");

		rel.r_offset -= sh_patch.sh_addr;
		if (!gelf_update_rela(data, i, &rel))
			kpfatalerror("gelf_update_rela");
	}
	return 1;
}

/* Undo symbol values from absolute binary offset back to relative
 * section offset
 */
static int
kpatch_rel_symbols_to_relative(kpatch_objinfo *patch)
{
	GElf_Shdr shdr;
	Elf_Scn *scn;

	size_t i, shndx = SHN_UNDEF;

	for (i = 0; i < patch->nsym; i++) {
		GElf_Sym s;

		if (!gelf_getsym(patch->symtab, i, &s))
			kpfatalerror("gelf_getsym");

		if (s.st_shndx == SHN_UNDEF ||
		    s.st_shndx >= SHN_LORESERVE ||
		    GELF_ST_TYPE(s.st_info) == STT_TLS ||
		    GELF_ST_TYPE(s.st_info) == STT_SECTION)
			continue;

		if (shndx != s.st_shndx) {
			scn = kpatch_objinfo_getshdr(patch, s.st_shndx,
						     &shdr);
			if (scn == NULL)
				kpfatalerror("kpatch_objinfo_getshdr");
			shndx = s.st_shndx;
		}

		if (shdr.sh_addr == 0)
			continue;

		s.st_value -= shdr.sh_addr;
		if (!gelf_update_sym(patch->symtab, i, &s))
			kpfatalerror("gelf_update_sym");
	}

	return 1;
}

static int *
map_patch_to_orig_sections(kpatch_objinfo *origbin,
			   kpatch_objinfo *patch)
{
	const char *patch_scnname, *orig_scnname;
	int *scn_mapping, *reverse_mapping;
	size_t iorig, ipatch;
	GElf_Shdr sh_orig, sh_patch;

	scn_mapping = calloc(origbin->shnum, sizeof(*scn_mapping));
	if (scn_mapping == NULL)
		return NULL;

	if (kpatch_objinfo_load(origbin) < 0)
		kpfatalerror("kpatch_load_object_info");

	if (kpatch_objinfo_load(patch) < 0)
		kpfatalerror("kpatch_load_object_info");

	for (iorig = 1, ipatch = 1; iorig < origbin->shnum; iorig++) {
		if (kpatch_objinfo_getshdr(origbin, iorig, &sh_orig) == NULL)
			kpfatalerror("kpatch_objinfo_getshdr");

		if (0 == (sh_orig.sh_flags & SHF_ALLOC))
			continue;

		orig_scnname = kpatch_objinfo_strptr(origbin,
						     SECTION_NAME,
						     sh_orig.sh_name);

		do {
			if (kpatch_objinfo_getshdr(patch, ipatch, &sh_patch) == NULL)
				kpfatalerror("kpatch_objinfo_getshdr");
			patch_scnname = kpatch_objinfo_strptr(patch, SECTION_NAME, sh_patch.sh_name);
			kpdebug("%s %s", orig_scnname, patch_scnname);
		} while (strcmp(orig_scnname, patch_scnname) != 0 &&
			 ++ipatch < patch->shnum);

		if (ipatch >= patch->shnum) {
			ipatch = 1;
			iorig++;
			kperr("unable to map %s original section, skipping",
			      orig_scnname);
			continue;
		}

		kpdebug("mapping section %s origshnum=%ld patchshnum=%ld",
			orig_scnname, iorig, ipatch);
		scn_mapping[iorig] = ipatch++;
	}

	reverse_mapping = calloc(patch->shnum, sizeof(*reverse_mapping));
	if (reverse_mapping == NULL) {
		free(scn_mapping);
		return NULL;
	}

	for (iorig = 1; iorig < origbin->shnum; iorig++) {
		if (scn_mapping[iorig] == 0)
			continue;
		reverse_mapping[scn_mapping[iorig]] = iorig;
	}

	free(scn_mapping);

	return reverse_mapping;
}

static int
kpatch_rel_copy_sections_addr(kpatch_objinfo *origbin, kpatch_objinfo *patch)
{
	size_t i;
	int *scn_mapping;
	Elf_Scn *scn_patch, *scn_orig;
	GElf_Shdr sh_patch, sh_orig;

	scn_mapping = map_patch_to_orig_sections(origbin, patch);
	if (scn_mapping == NULL)
		kpfatalerror("map_patch_to_orig_sections");

	for (i = 1; i < patch->shnum; i++) {
		if (scn_mapping[i] == 0)
			continue;

		scn_patch = kpatch_objinfo_getshdr(patch, i, &sh_patch);
		if (scn_patch == NULL)
			kpfatalerror("kpatch_objinfo_getshdr");

		scn_orig = kpatch_objinfo_getshdr(origbin, scn_mapping[i],
						  &sh_orig);
		if (scn_orig == NULL)
			kpfatalerror("kpatch_objinfo_getshdr");

		sh_patch.sh_addr = sh_orig.sh_addr;

		if (!gelf_update_shdr(scn_patch, &sh_patch))
			kpfatalerror("gelf_update_shdr");
	}

	free(scn_mapping);

	return 1;
}

static int
kpatch_undo_link(Elf *elf_origbin, Elf *elf_patch)
{
	Elf_Scn *scn_rel = NULL;
	GElf_Shdr sh_rel;
	int i;
	kpatch_objinfo origbin = OBJINFO_INIT(elf_origbin);
	kpatch_objinfo patch = OBJINFO_INIT(elf_patch);

	if (kpatch_objinfo_load(&origbin) < 0)
		kpfatalerror("kpatch_objinfo_load");

	if (kpatch_objinfo_load(&patch) < 0)
		kpfatalerror("kpatch_objinfo_load");

	/* Reset relocations offets and find symbol section */
	for (i = 1; i < patch.shnum; i++) {
		scn_rel = kpatch_objinfo_getshdr(&patch, i, &sh_rel);
		if (scn_rel == NULL)
			kpfatalerror("kpatch_objinfo_getshdr");

		if (sh_rel.sh_type == SHT_RELA) {
			if (!kpatch_rel_offset_to_relative(&patch, scn_rel,
							   &sh_rel))
				kpfatalerror("kpatch_rel_undo_offset_rela");
		}
		if (sh_rel.sh_type == SHT_REL)
			kpfatalerror("TODO: handle SHT_REL");
	}

	/* Redo symbols' values to section-relative */
	if (!kpatch_rel_symbols_to_relative(&patch))
		kpfatalerror("kpatch_rel_symbol_to_relative");

	/* Copy section `sh_addr'eses */
	if (!kpatch_rel_copy_sections_addr(&origbin, &patch))
		kpfatalerror("kpatch_rel_copy_sections_addr");

	/* Update object type */
	patch.ehdr.e_type = ET_REL;
	patch.ehdr.e_phoff = 0;
	patch.ehdr.e_phnum = 0;
	if (!gelf_update_ehdr(patch.elf, &patch.ehdr))
		kpfatalerror("gelf_update_ehdr");

	if (!elf_flagelf(patch.elf, ELF_C_SET, ELF_F_LAYOUT))
		kpfatalerror("elf_flagelf");
	if (elf_update(patch.elf, ELF_C_WRITE) < 0)
		kpfatalerror("elf_update");
	if (elf_end(patch.elf))
		kpfatalerror("elf_end");
	return 0;
}

int usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  kpatch_strip [options] -s/--strip <src.ko> <dst.ko>\n");
	fprintf(stderr, "  kpatch_strip [options] -r/--rel-fixup <orig-bin> <patch.o>\n");
	fprintf(stderr, "  kpatch_strip [options] -u/--undo-link <patch.o>\n");
	return -1;
}

enum {
	KCARE_USER = 130,
};

struct option long_opts[] = {
	{"strip", 0, NULL, 's'},
	{"rel-fixup", 0, NULL, 'r'},
	{"undo-link", 0, NULL, 'u'},
	{NULL, 0, NULL, 0}
};

#define SET_MODE(newmode)	do {					\
	if (mode) {							\
		kperr("ERROR: Multiple actions specified\n");		\
		return usage();						\
	}								\
	mode = newmode;				\
} while (0);

int main(int argc, char *argv[])
{
	Elf *elf1 = NULL, *elf2 = NULL;
	int ch, mode = 0;

	while ((ch = getopt_long(argc, argv, "+o:sru", long_opts, 0)) != -1) {
		switch (ch) {
		case 's':
			SET_MODE(MODE_STRIP);
			break;
		case 'r':
			SET_MODE(MODE_REL_FIXUP);
			break;
		case 'u':
			SET_MODE(MODE_UNDO_LINK);
			break;
		default:
			return usage();
		}
	}
	if (!mode)
		return usage();

	argc -= optind;
	argv += optind;

	switch (mode) {
	case MODE_STRIP:
	case MODE_FIXUP:
	case MODE_REL_FIXUP:
	case MODE_UNDO_LINK:
		if (argc != 2)
			return usage();
		break;
	default:
		return usage();
	}

	elf_version(EV_CURRENT);

	elf1 = kpatch_open_elf(argv[0], 0);
	if (argc == 2)
		elf2 = kpatch_open_elf(argv[1], (mode == MODE_STRIP));

	if (mode == MODE_STRIP)
		return kpatch_strip(elf1, elf2);
	if (mode == MODE_REL_FIXUP)
		return kpatch_rel_fixup(elf1, elf2);
	if (mode == MODE_UNDO_LINK)
		return kpatch_undo_link(elf1, elf2);
/*
*/
	return 0;
}
