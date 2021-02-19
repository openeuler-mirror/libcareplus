#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libunwind-ptrace.h>
#include <sys/utsname.h>

#include "include/kpatch_user.h"
#include "include/kpatch_coro.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"

asm (
    "makecontext_call:\n"
    "mov x29, sp\n"
    "and x29,x29,#-16\n"
    "sub x29, x29,#0x400\n"
    "ldr x9,[x29,#-128]\n"
    "str x9,[fp,#0x10]\n"
    //"str #128,[fp.#0x20]\n"
    "mov x0,fp\n"
    "mov x1,#0x100\n"
    "mov x2,#0\n"
    "svc #0\n"
    "brk #0\n"
    "makecontext_call_end:"
    );

extern unsigned char makecontext_call, makecontext_call_end;

int
locate_start_context_symbol(struct kpatch_process *proc,
			    unsigned long *pstart_context)
{
	struct object_file *olibc;
	struct user_regs_struct regs;
	int rv;
	unsigned long makecontext;

	olibc = kpatch_process_get_obj_by_regex(proc, "^libc-.*\\.so");
	if (olibc == NULL) {
		kpdebug("FAIL. Can't find libc\n");
		return -1;
	}

	rv = kpatch_resolve_undefined_single_dynamic(olibc,
						     "makecontext",
						     &makecontext);
	makecontext = vaddr2addr(olibc, makecontext);
	if (rv < 0 || makecontext == 0) {
		kpdebug("FAIL. Can't find makecontext\n");
		return -1;
	}

	regs.regs[8] = makecontext;
	rv = kpatch_execute_remote(proc2pctx(proc),
				   &makecontext_call,
				   &makecontext_call_end - &makecontext_call,
				   &regs);
	if (rv < 0) {
		kpdebug("FAIL. Can't execute makecontext\n");
		return -1;
	}

	rv = kpatch_process_mem_read(proc,
				     regs.regs[29]- STACK_OFFSET_START_CONTEXT,
				     pstart_context,
				     sizeof(*pstart_context));
	if (rv < 0) {
		kpdebug("FAIL. Can't peek __start_context address\n");
		return -1;
	}
	return rv;
}

int get_ptr_guard(struct kpatch_process *proc,
			 unsigned long *ptr_guard)
{
	int ret;
	unsigned long tls = 0;

    /*
	ret = kpatch_arch_prctl_remote(proc2pctx(proc), ARCH_GET_FS, &tls);
	if (ret < 0) {
		kpdebug("FAIL. Can't get TLS base value\n");
		return -1;
	}*/
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
		case UNW_AARCH64_X9:
			*val = regs[JB_RBX]; break;
		case UNW_AARCH64_X29:
			*val = regs[JB_RBP]; break;
		case UNW_AARCH64_X12...UNW_AARCH64_X15:
			*val = regs[reg - UNW_AARCH64_X12 + JB_R12]; break;
		case UNW_AARCH64_SP:
			*val = regs[JB_RSP]; break;
		case UNW_AARCH64_PC:
			*val = regs[JB_RIP]; break;
		default:
			return _UPT_access_reg(as, reg, val, write, arg);
	}
	return 0;
}
