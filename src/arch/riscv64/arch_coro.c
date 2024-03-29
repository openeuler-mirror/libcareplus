#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libunwind-ptrace.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/uio.h>

#include "include/kpatch_user.h"
#include "include/kpatch_coro.h"
#include "include/kpatch_common.h"
#include "include/kpatch_elf.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"

asm (
    "makecontext_call:\n"
    "mv fp, sp\n"
    "andi fp, fp, -16\n"
    /* ucontext_t is 0x3a8 bytes */
    "addi fp, fp, -0x400\n"
    "addi a0, fp, -128\n"
    "sd a0, 0x10(fp)\n"     // set uc_stack.ss_sp
    "li a0, 128\n"
    "sd a0, 0x20(fp)\n"     // set uc_stack.ss_size
    "mv a0, fp\n"
    "li a1, 0x100\n"
    "mv a2, zero\n"
    "jalr a7\n"     // makecontext(ucontext_t*, void (*)(), int argc, ...)
    "ebreak\n"
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

    olibc = kpatch_process_get_obj_by_regex(proc, "^libc\\.so");
    if (olibc == NULL) {
        kpdebug("FAIL. Can't find libc\n");
        return -1;
    }

    rv = kpatch_resolve_undefined_single_dynamic(olibc,
                             "makecontext", &makecontext);
    makecontext = vaddr2addr(olibc, makecontext);
    if (rv < 0 || makecontext == 0) {
        kpdebug("FAIL. Can't find makecontext\n");
        return -1;
    }

    regs.a7 = makecontext;
    rv = kpatch_execute_remote(proc2pctx(proc), &makecontext_call,
                   &makecontext_call_end - &makecontext_call, &regs);
    if (rv < 0) {
        kpdebug("FAIL. Can't execute makecontext\n");
        return -1;
    }

    rv = kpatch_process_mem_read(proc,
                     regs.s0 - STACK_OFFSET_START_CONTEXT,
                     pstart_context, sizeof(*pstart_context));
    if (rv < 0) {
        kpdebug("FAIL. Can't peek __start_context address\n");
        return -1;
    }
    return rv;
}

int get_ptr_guard(struct kpatch_process *proc,
             unsigned long *ptr_guard)
{
    (void)proc;
    (void)ptr_guard;
    kpinfo("NOTE: RISC-V not support pointer guard\n");
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
        case UNW_RISCV_PC:  // __pc
            *val = regs[0]; break;
        case UNW_RISCV_X8:  // __regs[0]
            *val = regs[1]; break;
        case UNW_RISCV_X9:  // __regs[1]
            *val = regs[2]; break;
        case UNW_RISCV_X18...UNW_RISCV_X27:// __regs[2-11]
            *val = regs[3 + reg - UNW_RISCV_X18]; break;
        case UNW_RISCV_X2:  // __sp
            *val = regs[13]; break;
        default:
            return _UPT_access_reg(as, reg, val, write, arg);
    }
    return 0;
}
