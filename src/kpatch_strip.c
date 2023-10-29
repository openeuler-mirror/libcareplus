/******************************************************************************
 * 2023.07.05 - strip: add 2 arch hooks to verify patches during strip
 * ISCAS ISRC Tarsier. <zhangkai@iscas.ac.cn>
 *
 * 2021.10.12 - strip: settle libcare-dump output elf file can't be objdump bug
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 *
 * 2021.10.11 - return: make every return properly other than direct-exit
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.11 - kpatch: fix code checker warning
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.11 - kpatch_strip: revert close fd
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
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

static Elf *kpatch_open_elf(const char *file, int create, int *elfd)
{
	Elf *elf = NULL;
	int fd;

	fd = open(file, O_RDWR | (create ? O_CREAT : 0), 0660);
	if (fd == -1) {
		kperr("Failed to open elf");
		return NULL;
	}
	elf = elf_begin(fd, (create ? ELF_C_WRITE : ELF_C_RDWR), NULL);
	if (!elf) {
		kperr("Failed to do elf_begin");
	}

	*elfd = fd;
	return elf;
}

static int check_info_len(struct kpatch_info *info, size_t scnsize)
{
	int ret = 0, i = 0;

        for (; i<scnsize; i++) {
	        if (is_new_func(&info[i])) {
	 	       continue;
		}

		if (info[i].dlen < 5) {
			kperr("too small function to patch at 0x%lx\n",
			      info[i].daddr);
			ret = 1;
		}

	}
	return ret;
}

#define KPATCH_INFO_LAST_SIZE	24

static int process_kpatch_info(Elf_Scn *scnout, GElf_Shdr *hdr)
{
	Elf_Data *prev = elf_getdata(scnout, NULL);
	Elf_Data *data = elf_newdata(scnout);
	static char info_term[KPATCH_INFO_LAST_SIZE];

	if (!prev) {
		kperr("Failed to get prev");
		return -1;
	}
	if (!data) {
		kperr("Failed to get newdata");
		return -1;
	}
	if (check_info_len((void*)prev->d_buf,
			   prev->d_size/sizeof(struct kpatch_info))) {
	kperr("Functions is too small to patch");
	return -1;
	}
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
	Elf_Data *dataout, *tmp;
	GElf_Shdr shin, shout;
	Elf64_Off off = -1ull;
	size_t shstridx;
	char *scnname;
	int offset;

	if (!gelf_newehdr(elfout, gelf_getclass(elfin))) {
		kperr("Failed to do gelf_newhdr");
		return -1;
	}
	if (!gelf_getehdr(elfout, &ehout)) {
		kperr("Failed to do gelf_getehdr out");
		return -1;
	}
	if (!gelf_getehdr(elfin, &ehin)) {
		kperr("Failed to do gelf_getehdr in");
		return -1;
	}
	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = ehin.e_ident[EI_DATA];
	ehout.e_machine = ehin.e_machine;
	ehout.e_type = ehin.e_type;
	ehout.e_version = ehin.e_version;
	ehout.e_shstrndx = ehin.e_shstrndx;
	ehout.e_shentsize = ehin.e_shentsize;
	ehout.e_phoff = 0;

	if (_elf_getshdrstrndx(elfin, &shstridx)) {
		kperr("Failed to do elf_getshdrstrndx");
		return -1;
	}
	while ((scnin = elf_nextscn(elfin, scnin)) != NULL) {
		scnout = elf_newscn(elfout);
		if (!scnout) {
			kperr("Failed to get elf_newscn");
			return -1;
		}
		if (!gelf_getshdr(scnout, &shout)) {
			kperr("Failed to do gelf_getshdr out");
			return -1;
		}
		if (!gelf_getshdr(scnin, &shin)) {
			kperr("Failed to do gelf_getshdr in");
			return -1;
		}
		scnname = elf_strptr(elfin, shstridx, shin.sh_name);
		if (!scnname) {
			kperr("Faild to do elf_strptr");
			return -1;
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
			if (!dataout) {
				kperr("Failed to do elf_newdata");
				return -1;
			}
			tmp = elf_getdata(scnin, NULL);
			if (tmp == NULL) {
				kperr("Failed to do elf_getdata");
				return -1;
			}
			*dataout = *tmp;
			off += shin.sh_size;
			if (!strcmp(scnname, ".kpatch.info")) {
				offset = process_kpatch_info(scnout, &shout);
				if (offset < 0) {
					kperr("Failed to process kpatch info");
					return -1;
				}
				off += (size_t)offset;
			}
		} else {
			kpinfo("don't need it\n");
			shout.sh_type = SHT_NOBITS;
                        /* destroy the .rela section sh_flags INFO property */
                        if (!strncmp(scnname, ".rela", 5))
                                shout.sh_flags = SHF_ALLOC;
		}
		if (!gelf_update_shdr(scnout, &shout)) {
			kperr("Failed to do gelf_update_shdr need");
			return -1;
		}
		if (!elf_flagscn(scnout, ELF_C_SET, ELF_F_DIRTY)) {
			kperr("Failed to do elf_flagscn");
			return -1;
		}
	}

	if (off == -1ull) {
		kperr("off is equal to -1");
		return -1;
	}

	off = ALIGN(off, 8);
	ehout.e_shoff = off;

	if (!gelf_update_ehdr(elfout, &ehout)) {
		kperr("Failed to do gelf_update_ehdr");
		return -1;
	}
	if (!elf_flagelf(elfout, ELF_C_SET, ELF_F_LAYOUT)) {
		kperr("Failed to do elf_flagelf");
		return -1;
	}
	if (elf_update(elfout, ELF_C_WRITE) < 0) {
		kperr("Failed to do elf_update");
		return -1;
	}
	if (elf_end(elfout)) {
		kperr("Failed to do elf_end");
		return -1;
	}
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

	if (!(scn = elf_getscn(oi->elf, sym->st_shndx))) {
		kperr("Failed to get elf_getscn origbin");
		return -1;
	}

	if (!gelf_getshdr(scn, &shdr)) {
		kperr("Failed to get gelf_getshdr origbin");
		return -1;
	}

	if (shdr.sh_addr > sym->st_value) {
		kperr("Shared libraries is not support");
		return -1;
	}
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

	if (kpatch_objinfo_load(origbin) < 0) {
		kperr("Failed to do kpatch_load_object_info");
		return SECTION_NOT_FOUND;
	}

	for (i = 0; i < origbin->nsym; i++) {
		if (!gelf_getsym(origbin->symtab, i, &s)) {
			kperr("Failed to do gelf_getsym origbin\n");
			return SECTION_NOT_FOUND;
		}
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

	return SECTION_NOT_FOUND;
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
		if (!gelf_getsym(oi->symtab, i, &sectionsym)) {
			kperr("Failed to do gelf_getsym\n");
			return SECTION_NOT_FOUND;
		}
		if (GELF_ST_TYPE(sectionsym.st_info) != STT_SECTION)
			continue;
		if (sectionsym.st_shndx == sym->st_shndx)
			break;
	}
	if (i == oi->nsym)
		return SECTION_NOT_FOUND;

	if (kpatch_get_symbol_offset_rel_section(oi, sym, symoff, secname) < 0)
		return SECTION_NOT_FOUND;

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
			kperr("Failed to do kpatch_fixup_rela_update_tls");

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

		if (status == SECTION_NOT_FOUND) {
			kperr("Unable to find local sym's section");
			return -1;
		}
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
				kpinfo("changing mov to lea at %lx\n", off);
				text[off] = LEA_INSN;
			}


			break;
		}

		/* deal with possible COPY dynamic relocs */
		rv = kpatch_arch_fixup_rela_copy(origbin, sym, symname);
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
	if (relatab == NULL) {
		kperr("Failed to do get relatab");
		return -1;
	}

	scn_text = kpatch_objinfo_getshdr(patch, sh_rel->sh_info, &sh_text);
	if (scn_text == NULL) {
		kperr("Failed to get scn_text");
		return -1;
	}

	data_text = elf_getdata(scn_text, NULL);
	if (data_text == NULL) {
		kperr("Failed to get data_text");
		return -1;
	}

	for (i = 0; i < nrel; i++) {
		GElf_Rela rel;
		GElf_Sym sym;

		if (!gelf_getrela(relatab, i, &rel)) {
			kperr("Failed to do gelf_getrela");
			return -1;
		}

		if (!gelf_getsym(symtab, GELF_R_SYM(rel.r_info), &sym)) {
			kperr("Failed to do gelf_getsym");
			return -1;
		}

		rv = kpatch_fixup_rela_one(origbin, patch, &rel, &sym,
					   &sh_text, data_text->d_buf);

		if (rv < 0)
			return rv;

		if (!gelf_update_rela(relatab, i, &rel)) {
			kperr("Failed to do gelf_update_rela");
			return -1;
		}

		if (rv &&
		    !gelf_update_sym(symtab, GELF_R_SYM(rel.r_info), &sym)) {
		    kperr("Failed to do gelf_update_sym");
			return -1;
		}
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


	if (kpatch_objinfo_load(&origbin)) {
		kperr("Failed to do kpatch_load_object_info");
		return -1;
	}

	if (kpatch_objinfo_load(&patch)) {
		kperr("Failed to do kpatch_load_object_info");
		return -1;
	}

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
			if (kpatch_fixup_rela(&origbin, &patch, scn_patch, &sh_patch) < 0) {
				kperr("Failed to do kpatch_fixup_rela");
				return -1;
			}

		if (sh_patch.sh_type == SHT_REL) {
			kperr("Unable to handle SHT_REL\n");
			return -1;
		}

		/* We had to update section headers otherwise updating a symbol
		   causes libelf to erase them completely, possibly a bug */
		if (!gelf_update_shdr(scn_patch, &sh_patch)) {
			kperr("Failed to do gelf_update_shdr");
			return -1;
		}
	}

	if (!elf_flagelf(elf_patch, ELF_C_SET, ELF_F_LAYOUT)) {
		kperr("Failed to do elf_flagelf");
		return -1;
	}
	if (elf_update(elf_patch, ELF_C_WRITE) < 0) {
		kperr("Failed to do elf_update");
		return -1;
	}
	if (elf_end(elf_patch)) {
		kperr("Failed to do elf_end");
		return -1;
	}
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

	memset(&sh_patch, 0, sizeof(GElf_Shdr));
	kpatch_objinfo_getshdr(patch, sh_rel->sh_info,
			       &sh_patch);

	if (sh_patch.sh_addr == 0)
		return 0;

	for (i = 0; i < nrel; i++) {
		GElf_Rela rel;

		if (!gelf_getrela(data, i, &rel)) {
			kperr("Failed to do gelf_getrela");
			return -1;
		}

		rel.r_offset -= sh_patch.sh_addr;
		if (!gelf_update_rela(data, i, &rel)) {
			kperr("Failed to do gelf_update_rela");
			return -1;
		}
	}

	return 0;
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

		if (!gelf_getsym(patch->symtab, i, &s)) {
			kperr("Failed to do gelf_getsym");
			return -1;
		}
		if (s.st_shndx == SHN_UNDEF ||
		    s.st_shndx >= SHN_LORESERVE ||
		    GELF_ST_TYPE(s.st_info) == STT_TLS ||
		    GELF_ST_TYPE(s.st_info) == STT_SECTION)
			continue;

		if (shndx != s.st_shndx) {
			scn = kpatch_objinfo_getshdr(patch, s.st_shndx,
						     &shdr);
			if (scn == NULL) {
				kperr("Failed to get scn");
				return -1;
			}
			shndx = s.st_shndx;
		}

		if (shdr.sh_addr == 0)
			continue;

		s.st_value -= shdr.sh_addr;
		if (!gelf_update_sym(patch->symtab, i, &s)) {
			kperr("Failed to update sym");
			return -1;
		}
	}

	return 0;
}

static int *
map_patch_to_orig_sections(kpatch_objinfo *origbin,
			   kpatch_objinfo *patch)
{
	const char *patch_scnname, *orig_scnname;
	int *scn_mapping = NULL;
	int *reverse_mapping = NULL;
	size_t iorig, ipatch;
	GElf_Shdr sh_orig, sh_patch;

	scn_mapping = calloc(origbin->shnum, sizeof(*scn_mapping));
	if (scn_mapping == NULL)
		return NULL;

	if (kpatch_objinfo_load(origbin) < 0) {
		kperr("Failed to do kpatch_load_object_info");
		goto cleanup;
	}

	if (kpatch_objinfo_load(patch) < 0) {
		kperr("Failed to do kpatch_load_object_info");
		goto cleanup;
	}

	for (iorig = 1, ipatch = 1; iorig < origbin->shnum; iorig++) {
		if (kpatch_objinfo_getshdr(origbin, iorig, &sh_orig) == NULL) {
			kperr("Failed to do kpatch_objinfo_getshdr");
			goto cleanup;
		}

		if ((sh_orig.sh_flags & SHF_ALLOC) == 0)
			continue;

		orig_scnname = kpatch_objinfo_strptr(origbin,
						     SECTION_NAME,
						     sh_orig.sh_name);

		do {
			if (kpatch_objinfo_getshdr(patch, ipatch, &sh_patch) == NULL) {
				kperr("Failed to do kpatch_objinfo_getshdr");
				goto cleanup;
			}
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
		goto cleanup;
	}

	for (iorig = 1; iorig < origbin->shnum; iorig++) {
		if (scn_mapping[iorig] == 0)
			continue;
		reverse_mapping[scn_mapping[iorig]] = iorig;
	}

cleanup:
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
	int ret = -1;

	scn_mapping = map_patch_to_orig_sections(origbin, patch);
	if (scn_mapping == NULL) {
		kperr("Failed to do map_patch_to_orig_sections");
		return -1;
	}

	for (i = 1; i < patch->shnum; i++) {
		if (scn_mapping[i] == 0)
			continue;

		scn_patch = kpatch_objinfo_getshdr(patch, i, &sh_patch);
		if (scn_patch == NULL) {
			kperr("Failed to get scn_patch");
			goto cleanup;
		}

		scn_orig = kpatch_objinfo_getshdr(origbin, scn_mapping[i],
						  &sh_orig);
		if (scn_orig == NULL) {
			kperr("Failed to get scn_orig");
			goto cleanup;
		}

		sh_patch.sh_addr = sh_orig.sh_addr;

		if (!gelf_update_shdr(scn_patch, &sh_patch)) {
			kperr("Fail to update shdr");
			goto cleanup;
		}
	}

	ret = 0;

cleanup:
	free(scn_mapping);
	return ret;
}

static int
kpatch_undo_link(Elf *elf_origbin, Elf *elf_patch)
{
	Elf_Scn *scn_rel = NULL;
	GElf_Shdr sh_rel;
	int i;
	kpatch_objinfo origbin = OBJINFO_INIT(elf_origbin);
	kpatch_objinfo patch = OBJINFO_INIT(elf_patch);

	if (kpatch_objinfo_load(&origbin) < 0) {
		kperr("Failed to load origbin");
		return -1;
	}

	if (kpatch_objinfo_load(&patch) < 0) {
		kperr("Failed to load patch");
		return -1;
	}

	/* Reset relocations offets and find symbol section */
	for (i = 1; i < patch.shnum; i++) {
		scn_rel = kpatch_objinfo_getshdr(&patch, i, &sh_rel);
		if (scn_rel == NULL) {
			kperr("Failed to get scn_rel");
			return -1;
		}

		if (sh_rel.sh_type == SHT_RELA) {
			if (kpatch_rel_offset_to_relative(&patch, scn_rel,
						&sh_rel) < 0) {
				kperr("Failed to do kpatch_rel_undo_offset_rela");
				return -1;
			}
		}
		if (sh_rel.sh_type == SHT_REL) {
			kperr("SHT_REL is not support");
			return -1;
		}
	}

	/* Redo symbols' values to section-relative */
	if (kpatch_rel_symbols_to_relative(&patch) < 0) {
		kperr("Failed to do kpatch_rel_symbol_to_relative");
		return -1;
	}

	/* deal with original function address bias problem */
	if (kpatch_arch_fixup_addr_bias(&origbin, &patch) == -1)
		return -1;

	/* Copy section `sh_addr'eses */
	if (kpatch_rel_copy_sections_addr(&origbin, &patch) < 0) {
		kperr("Failed to do kpatch_rel_copy_sections_addr");
		return -1;
	}

	/* Update object type */
	patch.ehdr.e_type = ET_REL;
	patch.ehdr.e_phoff = 0;
	patch.ehdr.e_phnum = 0;
	if (!gelf_update_ehdr(patch.elf, &patch.ehdr)) {
		kperr("Failed to update ehdr");
		return -1;
	}

	if (!elf_flagelf(patch.elf, ELF_C_SET, ELF_F_LAYOUT)) {
		kperr("Failed to do elf_flagelf");
		return -1;
	}

	if (elf_update(patch.elf, ELF_C_WRITE) < 0) {
		kperr("Failed to update elf");
		return -1;
	}

	if (elf_end(patch.elf)) {
		kperr("Failed to do elf_end");
		return -1;
	}

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
	int fd1 = -1;
	int fd2 = -1;
	int ret = -1;

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

	if (!mode) {
		return usage();
	}

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

	elf1 = kpatch_open_elf(argv[0], 0, &fd1);
	if (elf1 == NULL) {
		goto cleanup;
	}

	if (argc == 2) {
		elf2 = kpatch_open_elf(argv[1], (mode == MODE_STRIP), &fd2);
		if (elf2 == NULL) {
			goto cleanup;
		}
	}

	switch (mode) {
		case MODE_STRIP:
			ret = kpatch_strip(elf1, elf2);
			break;
		case MODE_REL_FIXUP:
			ret = kpatch_rel_fixup(elf1, elf2);
			break;
		case MODE_UNDO_LINK:
			ret = kpatch_undo_link(elf1, elf2);
			break;
		default:
			break;
	}

cleanup:
	if (fd1 >= 0)
		close(fd1);
	if (fd2 >= 0)
		close(fd2);

	return ret;
}
