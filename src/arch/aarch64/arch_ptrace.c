#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>

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

int kpatch_arch_prctl_remote(struct kpatch_ptrace_ctx *pctx, int code, unsigned long *addr)
{
	struct user_regs_struct regs;
	struct iovec regs_iov;
	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);

	unsigned long res, sp;
	int ret;

	kpdebug("arch_prctl_remote: %d, %p\n", code, addr);
	ret = ptrace(PTRACE_GETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&regs_iov);
	if (ret < 0) {
		kpdebug("FAIL. Can't get regs - %s\n", strerror(errno));
		return -1;
	}
	ret = kpatch_process_mem_read(pctx->proc,
				      regs.sp,
				      &sp,
				      sizeof(sp));
	if (ret < 0) {
		kplogerror("can't peek original stack data\n");
		return -1;
	}
	//ret = kpatch_syscall_remote(pctx, __NR_arch_prctl, code, regs.sp, 0, 0, 0, 0, &res);
	if (ret < 0)
		goto poke;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		ret = -1;
		goto poke;
	}
	ret = kpatch_process_mem_read(pctx->proc,
				      regs.sp,
				      &res,
				      sizeof(res));
	if (ret < 0)
		kplogerror("can't peek new stack data\n");

poke:
	if (kpatch_process_mem_write(pctx->proc,
				     &sp,
				     regs.sp,
				     sizeof(sp)))
		kplogerror("can't poke orig stack data\n");
	*addr = res;
	return ret;
}

int kpatch_arch_ptrace_resolve_ifunc(struct kpatch_ptrace_ctx *pctx,
                unsigned long *addr)
{
    struct user_regs_struct regs;

    unsigned char callrax[] = {
        0x00, 0x01, 0x3f, 0xd6, // blr x8
        0xa0, 0x00, 0x20, 0xd4, // brk #5
    };
    int ret;
    kpdebug("Executing callrax %lx (pid %d)\n", *addr, pctx->pid);
    regs.regs[8] = *addr;

    ret = kpatch_execute_remote(pctx, callrax, sizeof(callrax), &regs);
    if (ret == 0)
        *addr = regs.regs[0];

    return ret;
}

int
kpatch_arch_execute_remote_func(struct kpatch_ptrace_ctx *pctx,
			   const unsigned char *code,
			   size_t codelen,
			   struct user_regs_struct *pregs,
			   int (*func)(struct kpatch_ptrace_ctx *pctx,
				       void *data),
			   void *data)
{
	struct user_regs_struct orig_regs, regs;
	struct iovec orig_regs_iov, regs_iov;

	orig_regs_iov.iov_base = &orig_regs;
	orig_regs_iov.iov_len = sizeof(orig_regs);
	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);

	unsigned char orig_code[codelen];
	int ret;
	kpatch_process_t *proc = pctx->proc;
	unsigned long libc_base = proc->libc_base;


	ret = ptrace(PTRACE_GETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&orig_regs_iov);
	if (ret < 0) {
		kplogerror("can't get regs - %d\n", pctx->pid);
		return -1;
	}
	ret = kpatch_process_mem_read(
			      proc,
			      libc_base,
			      (unsigned long *)orig_code,
			      codelen);
	if (ret < 0) {
		kplogerror("can't peek original code - %d\n", pctx->pid);
		return -1;
	}
	ret = kpatch_process_mem_write(
			      proc,
			      (unsigned long *)code,
			      libc_base,
			      codelen);
	if (ret < 0) {
		kplogerror("can't poke syscall code - %d\n", pctx->pid);
		goto poke_back;
	}

	regs = orig_regs;
	regs.pc = libc_base;

	copy_regs(&regs, pregs);

	ret = ptrace(PTRACE_SETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&regs_iov);
	if (ret < 0) {
		kplogerror("can't set regs - %d\n", pctx->pid);
		goto poke_back;
	}

	ret = func(pctx, data);
	if (ret < 0) {
		kplogerror("failed call to func\n");
		goto poke_back;
	}

	ret = ptrace(PTRACE_GETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&regs_iov);
	if (ret < 0) {
		kplogerror("can't get updated regs - %d\n", pctx->pid);
		goto poke_back;
	}

	ret = ptrace(PTRACE_SETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&orig_regs_iov);
	if (ret < 0) {
		kplogerror("can't restore regs - %d\n", pctx->pid);
		goto poke_back;
	}

	*pregs = regs;

poke_back:
	kpatch_process_mem_write(
			proc,
			(unsigned long *)orig_code,
			libc_base,
			codelen);
	return ret;
}

void copy_regs(struct user_regs_struct *dst,
		      struct user_regs_struct *src)
{
#define COPY_REG(x) dst->x = src->x
       COPY_REG(regs[0]);
       COPY_REG(regs[1]);
       COPY_REG(regs[2]);
       COPY_REG(regs[3]);
       COPY_REG(regs[4]);
       COPY_REG(regs[5]);
       COPY_REG(regs[8]);
       COPY_REG(regs[29]);

       COPY_REG(regs[9]);
       COPY_REG(regs[10]);
       COPY_REG(regs[11]);
       COPY_REG(regs[12]);
       COPY_REG(regs[13]);
       COPY_REG(regs[14]);
       COPY_REG(regs[15]);
       COPY_REG(regs[16]);
       COPY_REG(regs[17]);
       COPY_REG(regs[18]);
       COPY_REG(regs[19]);
       COPY_REG(regs[20]);
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
	struct iovec regs_iov;

	regs_iov.iov_base = &regs;
	regs_iov.iov_len = sizeof(regs);

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

	ret = ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, (void *)&regs_iov);
	if (ret < 0) {
		kplogerror("can't get regs %d\n", pid);
		return -1;
	}

	pctx = kpatch_ptrace_find_thread(proc, pid, regs.pc);

	if (pctx == NULL) {
		/* We either don't know anything about this thread or
		 * even worse -- we stopped it in the wrong place.
		 * Bail out.
		 */
		pctx = kpatch_ptrace_find_thread(proc, pid, 0);
		if (pctx != NULL)
			pctx->running = 0;

		/* TODO: fix the latter by SINGLESTEPping such a thread with
		 * the original instruction in place */
		kperr("the thread ran out: %d, pc= %llx, expected = %lx\n", pid,
		      regs.pc, pctx->execute_until);
		errno = ESRCH;
		return -1;
	}

	pctx->running = 0;

	/* Restore thread registers, pctx is now valid */
	kpdebug("Got thread %d at %llx\n", pctx->pid,
		regs.pc - BREAK_INSN_LENGTH);

	regs.pc = pctx->execute_until;

	ret = ptrace(PTRACE_SETREGSET, pctx->pid, (void*)NT_PRSTATUS, (void*)&regs_iov);
	if (ret < 0) {
		kplogerror("can't set regs - %d\n", pctx->pid);
		return -1;
	}

	return 1;
}
