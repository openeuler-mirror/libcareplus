#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libunwind-ptrace.h>

#include <sys/utsname.h>

#include <asm/prctl.h>

#include "include/kpatch_user.h"
#include "include/kpatch_coro.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"

int get_ptr_guard(struct kpatch_process *proc,
			 unsigned long *ptr_guard)
{
	int ret;
	unsigned long tls;

	ret = kpatch_arch_prctl_remote(proc2pctx(proc), ARCH_GET_FS, &tls);
	if (ret < 0) {
		kpdebug("FAIL. Can't get TLS base value\n");
		return -1;
	}
	ret = kpatch_process_mem_read(proc,
				      tls + GLIBC_TLS_PTR_GUARD,
				      ptr_guard,
				      sizeof(*ptr_guard));
	if (ret < 0) {
		kpdebug("FAIL. Can't get pointer guard value\n");
		return -1;
	}

	return 0;
}

int _UCORO_access_reg(unw_addr_space_t as, unw_regnum_t reg, unw_word_t *val,
		      int write, void *arg)
{
	struct UCORO_info *info = (struct UCORO_info *)arg;
	unsigned long *regs = (unsigned long *)info->coro->env[0].__jmpbuf;

	if (write) {
		kperr("_UCORO_access_reg: write is not implemeneted (%d)\n", reg);
		return -UNW_EINVAL;
	}
	switch (reg) {
		case UNW_X86_64_RBX:
			*val = regs[JB_RBX]; break;
		case UNW_X86_64_RBP:
			*val = regs[JB_RBP]; break;
		case UNW_X86_64_R12...UNW_X86_64_R15:
			*val = regs[reg - UNW_X86_64_R12 + JB_R12]; break;
		case UNW_X86_64_RSP:
			*val = regs[JB_RSP]; break;
		case UNW_X86_64_RIP:
			*val = regs[JB_RIP]; break;
		default:
			return _UPT_access_reg(as, reg, val, write, arg);
	}
	return 0;
}
