/******************************************************************************
 * 2021.10.11 - kpatch: fix code checker warning
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - ptrace/process/patch: fix some bad code problem
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 *
 * 2021.10.08 - enhance kpatch_gensrc and kpatch_elf and kpatch_cc code
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 ******************************************************************************/

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/auxvec.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "include/kpatch_process.h"
#include "include/kpatch_common.h"
#include "include/kpatch_ptrace.h"
#include "include/kpatch_log.h"

#include <gelf.h>

static long read_gregs(int pid, struct user_regs_struct *regs)
{
    struct iovec data = {regs, sizeof(*regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &data) == -1) {
        kplogerror("ptrace(PTRACE_GETREGSET)");
        return -1;
    }
    return 0;
}

static long write_gregs(int pid, struct user_regs_struct *regs)
{
    struct iovec data = {regs, sizeof(*regs)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &data) == -1) {
        kplogerror("ptrace(PTRACE_SETREGSET)");
        return -1;
    }
    return 0;
}

/**
 * This is rather tricky since we are accounting for the non-main
 * thread calling for execve(). See `ptrace(2)` for details.
 *
 * FIXME(pboldin): this is broken for multi-threaded calls
 * to execve. Sight.
 */
int
kpatch_arch_ptrace_kickstart_execve_wrapper(kpatch_process_t *proc)
{
    int ret = 0;
    int pid = 0;
    struct kpatch_ptrace_ctx *pctx, *ptmp, *execve_pctx = NULL;
    long rv;
    struct user_regs_struct regs;

    kpdebug("kpatch_arch_ptrace_kickstart_execve_wrapper\n");

    list_for_each_entry(pctx, &proc->ptrace.pctxs, list) {
        /* proc->pid equals to THREAD ID of the thread
         * executing execve.so's version of execve
         */
        if (pctx->pid != proc->pid)
            continue;
        execve_pctx = pctx;
        break;
    }

    if (execve_pctx == NULL) {
        kperr("can't find thread executing execve\n");
        return -1;
    }

    /* Send a message to our `execve` wrapper so it will continue
     * execution
     */
    ret = send(proc->send_fd, &ret, sizeof(int), 0);
    if (ret < 0) {
        kplogerror("send failed\n");
        return ret;
    }

    /* Wait for it to reach BRKN instruction just before real execve */
    while (1) {
        ret = wait_for_stop(execve_pctx, NULL);
        if (ret < 0) {
            kplogerror("wait_for_stop\n");
            return ret;
        }

        rv = read_gregs(execve_pctx->pid, &regs);
        if (rv == -1)
            return rv;

        rv = ptrace(PTRACE_PEEKTEXT, execve_pctx->pid, regs.pc, NULL);
        if ((rv == -1) && errno)
            return rv;
        if ((unsigned)rv == *(unsigned*)(char[])BREAK_INSN)
            break;
    }

    /* Wait for SIGTRAP from the execve. It happens from the thread
     * group ID, so find it if thread doing execve() is not it. */
    if (execve_pctx != proc2pctx(proc)) {
        pid = get_threadgroup_id(proc->pid);
        if (pid < 0)
            return -1;

        proc->pid = pid;
    }

    ret = wait_for_stop(execve_pctx, (void *)(uintptr_t)pid);
    if (ret < 0) {
        kplogerror("waitpid\n");
        return ret;
    }

    list_for_each_entry_safe(pctx, ptmp, &proc->ptrace.pctxs, list) {
        if (pctx->pid == proc->pid)
            continue;
        kpatch_ptrace_detach(pctx);
        kpatch_ptrace_ctx_destroy(pctx);
    }

    /* Suddenly, /proc/pid/mem gets invalidated */
    {
        char buf[sizeof("/proc/0123456789/mem")];
        close(proc->memfd);

        snprintf(buf, sizeof(buf), "/proc/%d/mem", proc->pid);
        proc->memfd = open(buf, O_RDWR);
        if (proc->memfd < 0) {
            kplogerror("Failed to open proc mem\n");
            return -1;
        }
    }

    kpdebug("...done\n");

    return 0;
}

int
wait_for_mmap(struct kpatch_ptrace_ctx *pctx,
          unsigned long *pbase)
{
    int ret, status = 0, insyscall = 0;
    long rv;
    struct user_regs_struct regs;

    while (1) {
        ret = ptrace(PTRACE_SYSCALL, pctx->pid, NULL,
                 (void *)(uintptr_t)status);
        if (ret < 0) {
            kplogerror("can't PTRACE_SYSCALL tracee - %d\n",
                   pctx->pid);
            return -1;
        }

        ret = waitpid(pctx->pid, &status, __WALL);
        if (ret < 0) {
            kplogerror("can't wait tracee - %d\n", pctx->pid);
            return -1;
        }

        if (WIFEXITED(status)) {
            status = WTERMSIG(status);
            continue;
        } else if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
            status = 0;
            continue;
        }

        status = 0;

        if (insyscall == 0) {
            rv = read_gregs(pctx->pid, &regs);
            if (rv == -1)
                return -1;
            insyscall = regs.a7;
            continue;
        } else if (insyscall == __NR_mmap) {
            rv = read_gregs(pctx->pid, &regs);
            if (rv == -1)
                return -1;
            *pbase = regs.a0;
            break;
        }

        insyscall = !insyscall;
    }

    return 0;
}

int kpatch_arch_syscall_remote(struct kpatch_ptrace_ctx *pctx, int nr,
                   unsigned long arg1, unsigned long arg2, unsigned long arg3,
                   unsigned long arg4, unsigned long arg5, unsigned long arg6,
                   unsigned long *res)
{
    struct user_regs_struct regs;
    unsigned char syscall[] = {
        0x73, 0x00, 0x00, 0x00, // ecall
        0x73, 0x00, 0x10, 0x00, // ebreak
    };
    int ret;

    kpdebug("Executing syscall %d (pid %d)...\n", nr, pctx->pid);
    regs.a7 = (unsigned long)nr;
    regs.a0 = arg1;
    regs.a1 = arg2;
    regs.a2 = arg3;
    regs.a3 = arg4;
    regs.a4 = arg5;
    regs.a5 = arg6;

    ret = kpatch_execute_remote(pctx, syscall, sizeof(syscall), &regs);
    if (ret == 0)
        *res = regs.a0;

    return ret;
}

int kpatch_arch_ptrace_resolve_ifunc(struct kpatch_ptrace_ctx *pctx,
                                     unsigned long *addr)
{
    struct user_regs_struct regs;
    unsigned char callrax[] = {
        0xe7, 0x00, 0x05, 0x00, // jalr a0
        0x73, 0x00, 0x10, 0x00, // ebreak
    };
    int ret;

    kpdebug("Executing callrax %lx (pid %d)\n", *addr, pctx->pid);
    regs.a0 = *addr;

    ret = kpatch_execute_remote(pctx, callrax, sizeof(callrax), &regs);
    if (ret == 0)
        *addr = regs.a0;

    return ret;
}

int
kpatch_arch_execute_remote_func(struct kpatch_ptrace_ctx *pctx,
               const unsigned char *code,
               size_t codelen,
               struct user_regs_struct *pregs,
               int (*func)(struct kpatch_ptrace_ctx *pctx, const void *data),
               const void *data)
{
    struct user_regs_struct orig_regs, regs;
    unsigned char orig_code[codelen];
    int ret;
    kpatch_process_t *proc = pctx->proc;
    unsigned long libc_base = proc->libc_base;


    ret = read_gregs(pctx->pid, &orig_regs);
    if (ret < 0)
        return -1;
    ret = kpatch_process_mem_read(proc, libc_base,
                (unsigned long *)orig_code, codelen);
    if (ret < 0) {
        kplogerror("can't peek original code - %d\n", pctx->pid);
        return -1;
    }
    ret = kpatch_process_mem_write(proc, (unsigned long *)code,
                  libc_base, codelen);
    if (ret < 0) {
        kplogerror("can't poke syscall code - %d\n", pctx->pid);
        goto poke_back;
    }

    /* set new regs: original regs with new pc, new copy-regs(arguments) */
    regs = orig_regs;
    regs.pc = libc_base;
    copy_regs(&regs, pregs);
    ret = write_gregs(pctx->pid, &regs);
    if (ret < 0)
        goto poke_back;

    ret = func(pctx, data);
    if (ret < 0) {
        kplogerror("failed call to func\n");
        goto poke_back;
    }

    ret = read_gregs(pctx->pid, &regs);
    if (ret < 0)
        goto poke_back;

    ret = write_gregs(pctx->pid, &orig_regs);
    if (ret < 0)
        goto poke_back;

    *pregs = regs;

poke_back:
    kpatch_process_mem_write(proc, (unsigned long *)orig_code,
            libc_base, codelen);
    return ret;
}

void copy_regs(struct user_regs_struct *dst, struct user_regs_struct *src)
{
#define COPY_REG(x) dst->x = src->x
       COPY_REG(a0);
       COPY_REG(a1);
       COPY_REG(a2);
       COPY_REG(a3);
       COPY_REG(a4);
       COPY_REG(a5);
       COPY_REG(a6);
       COPY_REG(a7);
#undef COPY_REG
}

int
kpatch_arch_ptrace_waitpid(kpatch_process_t *proc,
               struct timespec *timeout,
               const sigset_t *sigset)
{
    struct kpatch_ptrace_ctx *pctx;
    siginfo_t siginfo;
    int ret, status;
    pid_t pid;
    struct user_regs_struct regs;

    /* Immediately reap one attached thread */
    pid = waitpid(-1, &status, __WALL | WNOHANG);

    if (pid < 0) {
        kplogerror("can't wait for tracees\n");
        return -1;
    }

    /* There is none ready, wait for notification via signal */
    if (pid == 0) {
        ret = sigtimedwait(sigset, &siginfo, timeout);
        if (ret == -1 && errno == EAGAIN) {
            /* We have timeouted */
            return -1;
        }

        if (ret == -1 && errno == EINVAL) {
            kperr("invalid timeout\n");
            return -1;
        }

        /* We have got EINTR and must restart */
        if (ret == -1 && errno == EINTR)
            return 0;

        /**
         * Kernel stacks signals that follow too quickly.
         * Deal with it by waiting for any child, not just
         * one that is specified in signal
         */
        pid = waitpid(-1, &status, __WALL | WNOHANG);

        if (pid == 0) {
            kperr("missing waitpid for %d\n", siginfo.si_pid);
            return 0;
        }

        if (pid < 0) {
            kplogerror("can't wait for tracee %d\n", siginfo.si_pid);
            return -1;
        }
    }

    if (!WIFSTOPPED(status) && WIFSIGNALED(status)) {
        /* Continue, resending the signal */
        ret = ptrace(PTRACE_CONT, pid, NULL,
                 (void *)(uintptr_t)WTERMSIG(status));
        if (ret < 0) {
            kplogerror("can't start tracee %d\n", pid);
            return -1;
        }
        return 0;
    }

    if (WIFEXITED(status)) {
        pctx = kpatch_ptrace_find_thread(proc, pid, 0UL);
        if (pctx == NULL) {
            kperr("got unexpected child '%d' exit\n", pid);
        } else {
            /* It's dead */
            pctx->pid = pctx->running = 0;
        }
        return 1;
    }

    ret = read_gregs(pid, &regs);
    if (ret < 0)
        return -1;

    pctx = kpatch_ptrace_find_thread(proc, pid, regs.pc);

    if (pctx == NULL) {
        /* We either don't know anything about this thread or
         * even worse -- we stopped it in the wrong place.
         * Bail out.
         */
        pctx = kpatch_ptrace_find_thread(proc, pid, 0);
        if (pctx != NULL) {
            pctx->running = 0;
            kperr("the thread ran out: %d, pc= %lx, expected = %lx\n",
                    pid, regs.pc, pctx->execute_until);
        } else {
            kperr("the thread ran out: %d, pc= %lx\n", pid, regs.pc);
        }

        /* TODO: fix the latter by SINGLESTEPping such a thread with
         * the original instruction in place */
        errno = ESRCH;
        return -1;
    }

    pctx->running = 0;

    /* Restore thread registers, pctx is now valid */
    kpdebug("Got thread %d at %lx\n", pctx->pid,
        regs.pc - BREAK_INSN_LENGTH);

    regs.pc = pctx->execute_until;

    ret = write_gregs(pctx->pid, &regs);
    if (ret < 0)
        return -1;

    return 1;
}
