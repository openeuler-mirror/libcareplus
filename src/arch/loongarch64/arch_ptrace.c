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

/* LoongArch register indices */ 
#define REG_A0 4
#define REG_A1 5
#define REG_A2 6
#define REG_A3 7 
#define REG_A4 8 
#define REG_A5 9 
#define REG_A6 10 
#define REG_A7 11
#define REG_PC csr_era


static long read_gregs(int pid, struct user_regs_struct *regs)
{ 
    struct iovec data = {regs, sizeof(*regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &data) == -1) { 
        kplogerror("ptrace(PTRACE_GETREGS)"); 
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

        rv = ptrace(PTRACE_PEEKTEXT, execve_pctx->pid, (void *)regs.REG_PC, NULL);
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
            insyscall = regs.regs[REG_A7];
            continue;
        } else if (insyscall == __NR_mmap) {
            rv = read_gregs(pctx->pid, &regs);
            if (rv == -1)
                return -1;
            *pbase = regs.REG_PC;
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
        0x00, 0x00, 0x2b, 0x00, // syscall  0
        0x00, 0x00, 0x2a, 0x00  // break  0
    };
    int ret;

    kpdebug("Executing syscall %d (pid %d)...\n", nr, pctx->pid);
    memset(&regs, 0, sizeof(regs));
    regs.regs[REG_A7] = (unsigned long)nr;
    regs.regs[REG_A0] = arg1;
    regs.regs[REG_A1] = arg2;
    regs.regs[REG_A2] = arg3;
    regs.regs[REG_A3] = arg4;
    regs.regs[REG_A4] = arg5;
    regs.regs[REG_A5] = arg6;

    ret = kpatch_execute_remote(pctx, syscall, sizeof(syscall), &regs);
    if (ret == 0)
        *res = regs.regs[REG_A0];
        

    return ret;
}

int kpatch_arch_ptrace_resolve_ifunc(struct kpatch_ptrace_ctx *pctx,
                                     unsigned long *addr)
{
    struct user_regs_struct regs;
    unsigned char call_ra[] = {
        0x81, 0x00, 0x00, 0x4c,  // jirl ra, r4, 0
        0x00, 0x00, 0x2a, 0x00,  // break 0
    };
    int ret;

    kpdebug("Executing call_ra %lx (pid %d)\n", *addr, pctx->pid);
    memset(&regs, 0, sizeof(regs));
    regs.regs[REG_A0] = *addr;

    ret = kpatch_execute_remote(pctx, call_ra, sizeof(call_ra), &regs);
    if (ret == 0)
        *addr = regs.regs[REG_A0];

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
    regs.REG_PC = libc_base;
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
#define COPY_REG(x) dst->regs[x] = src->regs[x]
       COPY_REG(REG_A0);
       COPY_REG(REG_A1);
       COPY_REG(REG_A2);
       COPY_REG(REG_A3);
       COPY_REG(REG_A4);
       COPY_REG(REG_A5);
       COPY_REG(REG_A6);
       COPY_REG(REG_A7);
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

    pctx = kpatch_ptrace_find_thread(proc, pid, regs.REG_PC);

    if (pctx == NULL) {
        /* We either don't know anything about this thread or
         * even worse -- we stopped it in the wrong place.
         * Bail out.
         */
        pctx = kpatch_ptrace_find_thread(proc, pid, 0);
        if (pctx != NULL) {
            pctx->running = 0;
            kperr("the thread ran out: %d, pc= %lx, expected = %lx\n",
                    pid, regs.REG_PC, pctx->execute_until);
        } else {
            kperr("the thread ran out: %d, pc= %lx\n", pid, regs.REG_PC);
        }

        /* TODO: fix the latter by SINGLESTEPping such a thread with
         * the original instruction in place */
        errno = ESRCH;
        return -1;
    }

    pctx->running = 0;

    /* Restore thread registers, pctx is now valid */
    kpdebug("Got thread %d at %lx\n", pctx->pid,
        regs.REG_PC - BREAK_INSN_LENGTH);

    regs.REG_PC = pctx->execute_until;

    ret = write_gregs(pctx->pid, &regs);
    if (ret < 0)
        return -1;

    return 1;
}
