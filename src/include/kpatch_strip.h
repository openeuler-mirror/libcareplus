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
 ******************************************************************************/

#ifndef __KPATCH_STRIP_H__
#define __KPATCH_STRIP_H__

int
kpatch_get_original_symbol_loc(kpatch_objinfo *origbin,
                   const char *symname,
                   size_t *symoff,
                   const char **secname);

int
kpatch_arch_fixup_rela_update_tls(kpatch_objinfo *origbin,
		kpatch_objinfo *patch,
		GElf_Rela *rela,
		GElf_Sym *sym,
		GElf_Shdr *sh_text,
		unsigned char *text);

#endif
