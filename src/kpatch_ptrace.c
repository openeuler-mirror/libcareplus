/******************************************************************************
 * 2021.10.12 - misc: add -D_FORTIFY_SOURCE=2 and fix return check
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - ptrace/process/patch: fix some bad code problem
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
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

/* process's memory access */
int
kpatch_process_mem_read(kpatch_process_t *proc,
			unsigned long src,
			void *dst,
			size_t size)
{
	return pread(proc->memfd, dst, size, (off_t)src);
}

static int
kpatch_process_mem_write_ptrace(kpatch_process_t *proc,
				void *src,
				unsigned long dst,
				size_t size)
{
	int ret;

	while (ROUND_DOWN(size, sizeof(long)) != 0) {
		ret = ptrace(PTRACE_POKEDATA, proc->pid, dst,
			     *(unsigned long *)src);
		if (ret)
			return -1;

		dst += sizeof(long);
		src += sizeof(long);
		size -= sizeof(long);
	}

	if (size) {
		unsigned long tmp;

		tmp = ptrace(PTRACE_PEEKDATA, proc->pid, dst, NULL);
		if (tmp == (unsigned long)-1 && errno)
			return -1;
		memcpy(&tmp, src, size);

		ret = ptrace(PTRACE_POKEDATA, proc->pid, dst, tmp);
		if (ret)
			return -1;
	}

	return 0;
}

int
kpatch_process_mem_write(kpatch_process_t *proc,
			 void *src,
			 unsigned long dst,
			 size_t size)
{
	static int use_pwrite = 1;
	ssize_t w;

	if (use_pwrite)
		w = pwrite(proc->memfd, src, size, (off_t)dst);
	if (!use_pwrite || (w == -1 && errno == EINVAL)) {
		use_pwrite = 0;
		return kpatch_process_mem_write_ptrace(proc, src, dst, size);
	}

	return w != size ? -1 : 0;
}

struct process_mem_iter *
kpatch_process_mem_iter_init(kpatch_process_t *proc)
{
	struct process_mem_iter *iter;
	size_t pagesize = sysconf(_SC_PAGESIZE);

	iter = malloc(sizeof(*iter) + pagesize);
	if (!iter)
		return NULL;

	iter->proc = proc;
	iter->buflen = 0;

	iter->buffer_size = pagesize;

	return iter;
}

void kpatch_process_mem_iter_free(struct process_mem_iter *iter)
{
	free(iter);
}

int kpatch_process_mem_iter_peek(struct process_mem_iter *iter,
				 void *dst, size_t size,
				 unsigned long remote_addr)
{
	if (size > iter->buffer_size) {
		return kpatch_process_mem_read(iter->proc, remote_addr, dst, size);
	}

	if (iter->buflen == 0 ||
	    remote_addr < iter->base ||
	    remote_addr + size > iter->base + iter->buflen) {
		int ret;

		iter->base = remote_addr;
		ret = kpatch_process_mem_read(iter->proc,
					      remote_addr,
					      iter->buffer,
					      iter->buffer_size);
		if (ret < size)
			return -1;
		iter->buflen = ret;
	}

	memcpy(dst, iter->buffer + (remote_addr - iter->base), size);
	return 0;
}

int kpatch_process_mem_iter_peek_ulong(struct process_mem_iter *iter,
				       unsigned long *dst,
				       unsigned long remote_addr)
{
	return kpatch_process_mem_iter_peek(iter, dst, sizeof(*dst), remote_addr);
}

int kpatch_ptrace_get_entry_point(struct kpatch_ptrace_ctx *pctx,
				  unsigned long *pentry_point)
{
	int fd, ret;
	unsigned long entry[2] = { AT_NULL, 0 };
	char path[sizeof("/proc/0123456789/auxv")];

	kpdebug("Looking for entry point...");

	sprintf(path, "/proc/%d/auxv", pctx->pid);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		kplogerror("can't open %s\n", path);
		return -1;
	}

	do {
		ret = read(fd, entry, sizeof(entry));
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret != sizeof(entry))
			break;

		if (entry[0] == AT_ENTRY) {
			*pentry_point = entry[1];
			break;
		}
	} while (1);

	if (ret < 0)
		kplogerror("reading %s\n", path);

	close(fd);

	return entry[0] == AT_ENTRY ? 0 : -1;
}


struct kpatch_ptrace_ctx *
kpatch_ptrace_find_thread(kpatch_process_t *proc,
			  pid_t pid,
			  unsigned long rip)
{
	struct kpatch_ptrace_ctx *pctx;

	for_each_thread(proc, pctx) {
		/* Check that we stopped the right thread */
		if (pctx->pid == pid) {
			if (rip == 0UL)
				return pctx;

			if (pctx->execute_until != 0UL &&
			    rip == pctx->execute_until + BREAK_INSN_LENGTH)
				return pctx;

			break;
		}
	}

	return NULL;
}

struct breakpoint {
	unsigned long addr;
	unsigned char orig_code[BREAK_INSN_LENGTH];
};

/* NOTE(pboldin) this code is pretty confusing and surely is platform-specific
 * in sense of the kernel version. This should be more extensively tested */
int
kpatch_ptrace_execute_until(kpatch_process_t *proc,
			    int timeout_msec,
			    unsigned int flags)
{
	int ret = 0, errno_save;
	char break_code[] = BREAK_INSN;
	struct breakpoint *bkpts;
	size_t has_target, running, to_be_stopped, bkpt_installed, i;
	sigset_t sigset, oldsigset;
	struct timespec timeout, start, current;

	struct kpatch_ptrace_ctx *pctx;

	has_target = 0;
	for_each_thread(proc, pctx)
		if (pctx->execute_until != 0UL)
			has_target++;

	if (has_target == 0)
		return 0;

	bkpts = calloc(has_target, sizeof(*bkpts));
	if (bkpts == NULL)
		return -1;

	bkpt_installed = 0;
	for_each_thread(proc, pctx) {

		if (pctx->execute_until == 0UL)
			continue;

		for (i = 0; i < bkpt_installed; i++) {
			if (bkpts[i].addr == pctx->execute_until)
				break;
		}

		if (i != bkpt_installed) {
			kpdebug("breakpoint at %lx already installed\n",
				pctx->execute_until);
			continue;
		}

		bkpts[bkpt_installed].addr = pctx->execute_until;

		kpdebug("Installing break at %lx...\n",
			bkpts[bkpt_installed].addr);

		ret = kpatch_process_mem_read(proc,
				bkpts[bkpt_installed].addr,
				(void *)bkpts[bkpt_installed].orig_code,
				BREAK_INSN_LENGTH);
		if (ret < 0) {
			kplogerror("cannot read orig code - %d\n", pctx->pid);
			goto poke_back;
		}

		ret = kpatch_process_mem_write(proc,
				break_code,
				bkpts[bkpt_installed].addr,
				BREAK_INSN_LENGTH);
		if (ret < 0) {
			kplogerror("cannot write break code - %d\n", pctx->pid);
			goto poke_back;
		}

		bkpt_installed++;
	}

	/* Block the SIGCHLD so we can use sigtimedwait */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigset, &oldsigset) < 0)
		goto poke_back;

	running = 0;
	for_each_thread(proc, pctx) {
		kpdebug("Continuing thread %d until %lx...\n", pctx->pid, pctx->execute_until);

		if (!(flags & EXECUTE_ALL_THREADS) && pctx->execute_until == 0UL)
			continue;

		ret = ptrace(PTRACE_CONT, pctx->pid, NULL, NULL);
		if (ret < 0) {
			kplogerror("can't start tracee - %d\n", pctx->pid);
			goto restore_signals;
		}
		pctx->running = 1;
		running++;
	}

	to_be_stopped = has_target;
	while (running != 0 && to_be_stopped != 0 && timeout_msec >= 0) {
		int rv, dt;

		timeout.tv_sec = timeout_msec / SEC_TO_MSEC;
		timeout.tv_nsec = (timeout_msec % SEC_TO_MSEC) * MSEC_TO_NSEC;

		if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
			kplogerror("can't get start time\n");
			break;
		}

		rv = kpatch_arch_ptrace_waitpid(proc, &timeout, &sigset);
		if (rv < 0)
			break;

		if (clock_gettime(CLOCK_MONOTONIC, &current) < 0) {
			kplogerror("can't get current time\n");
			break;
		}

		if (rv == 1) {
			to_be_stopped--;
			running--;
		}

		dt = (current.tv_sec - start.tv_sec) * SEC_TO_MSEC +
		     (current.tv_nsec - start.tv_nsec) / MSEC_TO_NSEC;

		timeout_msec -= dt;

		kpdebug("Passed %d msecs\n", dt);
	}

	kpdebug("left %d msecs\n", timeout_msec);

restore_signals:
	errno_save = errno;
	if (sigprocmask(SIG_SETMASK, &oldsigset, NULL) < 0) {
		kplogerror("unable to restore original signals\n");
	}
	errno = errno_save;

poke_back:
	errno_save = errno;

	i = 0;
	for_each_thread(proc, pctx) {
		int status;

		if (!pctx->running)
			continue;

		if (syscall(SYS_tgkill, proc->pid, pctx->pid, SIGSTOP) < 0)
			kplogerror("can't tkill %d\n", pctx->pid);

		while (errno != ESRCH && errno != ECHILD) {
			ret = waitpid(pctx->pid, &status, __WALL);
			if (ret < 0)
				kplogerror("can't wait for %d\n",
					   pctx->pid);

			if (WIFSTOPPED(status) || WIFEXITED(status) ||
			    errno == ECHILD)
				break;

			status = WTERMSIG(status);
			ret = ptrace(PTRACE_CONT, pctx->pid, NULL,
				     (void *)(uintptr_t)status);
			if (ret < 0)
				kplogerror("Can't continue thread %d\n",
					   pctx->pid);
		}

		pctx->running = 0;
	}

	for (i = 0; i < bkpt_installed; i++) {
		ret = kpatch_process_mem_write(
			proc,
			(void *)bkpts[i].orig_code,
			bkpts[i].addr,
			BREAK_INSN_LENGTH);

		if (ret < 0) {
			kplogerror("can't restore breakpoint - %lx\n",
				   bkpts[i].addr);
		}

		for_each_thread(proc, pctx)
			if (pctx->execute_until == bkpts[i].addr)
				pctx->execute_until = 0;
	}

	for_each_thread(proc, pctx) {
		if (pctx->execute_until != 0UL)
			kpwarn("thread %d still wants to break at 0x%lx\n",
			       pctx->pid, pctx->execute_until);
	}

	free(bkpts);

	if (i != bkpt_installed)
		kpwarn("Missing some original code, huh?\n");

	errno = errno_save;

	return ret;
}

int
wait_for_stop(struct kpatch_ptrace_ctx *pctx,
	      const void *data)
{
	int ret, status = 0, pid = (int)(uintptr_t)data ?: pctx->pid;
	kpdebug("wait_for_stop(pctx->pid=%d, pid=%d)\n", pctx->pid, pid);

	while (1) {
		ret = ptrace(PTRACE_CONT, pctx->pid, NULL,
			     (void *)(uintptr_t)status);
		if (ret < 0) {
			kplogerror("can't start tracee %d\n", pctx->pid);
			return -1;
		}

		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			kplogerror("can't wait tracee %d\n", pid);
			return -1;
		}

		if (WIFSTOPPED(status))  {
			if (WSTOPSIG(status) == SIGSTOP ||
			    WSTOPSIG(status) == SIGTRAP)
				break;
			status = WSTOPSIG(status);
			continue;
		}

		status = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	}

	return 0;
}

int
kpatch_execute_remote(struct kpatch_ptrace_ctx *pctx,
		      const unsigned char *code,
		      size_t codelen,
		      struct user_regs_struct *pregs)
{
	return kpatch_arch_execute_remote_func(pctx,
					  code,
					  codelen,
					  pregs,
					  wait_for_stop,
					  NULL);
}

/* FIXME(pboldin) buf might be too small */
int
get_threadgroup_id(int tid)
{
	FILE *fh;
	char buf[256];
	int pid = -1;

	sprintf(buf, "/proc/%d/status", tid);

	fh = fopen(buf, "r");
	if (fh == NULL)
		return -1;

	while (!feof(fh)) {
		if (fscanf(fh, "Tgid: %d", &pid) == 1) {
			break;
		}
		if (fgets(buf, sizeof(buf), fh) == NULL) {
			break;
		}
	}

	fclose(fh);
	return pid;
}

unsigned long
kpatch_mmap_remote(struct kpatch_ptrace_ctx *pctx,
		   unsigned long addr,
		   size_t length,
		   int prot,
		   int flags,
		   int fd,
		   off_t offset)
{
	int ret;
	unsigned long res;

	kpdebug("mmap_remote: 0x%lx+%lx, %x, %x, %d, %lx\n", addr, length,
		prot, flags, fd, offset);
	ret = kpatch_arch_syscall_remote(pctx, __NR_mmap, (unsigned long)addr,
				    length, prot, flags, fd, offset, &res);
	if (ret < 0)
		return 0;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		return 0;
	}
	return res;
}

int kpatch_munmap_remote(struct kpatch_ptrace_ctx *pctx,
			 unsigned long addr,
			 size_t length)
{
	int ret;
	unsigned long res;

	kpdebug("munmap_remote: 0x%lx+%lx\n", addr, length);
	ret = kpatch_arch_syscall_remote(pctx, __NR_munmap, (unsigned long)addr,
				    length, 0, 0, 0, 0, &res);
	if (ret < 0)
		return -1;
	if (ret == 0 && res >= (unsigned long)-MAX_ERRNO) {
		errno = -(long)res;
		return -1;
	}
	return 0;
}

int
kpatch_remote_write(struct kpatch_ptrace_ctx *pctx,
		    unsigned long dst,
		    void *src,
		    size_t size)
{
	int ret;

	kpdebug("Copying 0x%lx bytes to target process's 0x%lx...", size, dst);
	ret = kpatch_process_mem_write(pctx->proc, src, dst, size);
	if (ret < 0)
		kpdebug("FAIL\n");
	else
		kpdebug("OK\n");
	return ret;
}

int
kpatch_process_memcpy(kpatch_process_t *proc,
		      unsigned long dst,
		      unsigned long src,
		      size_t size)
{
	int ret;
	char *buf;

	kpdebug("Copying 0x%lx bytes from 0x%lx to 0x%lx in target...",
		size, src, dst);

	buf = malloc(size);
	if (buf == NULL) {
		kpdebug("FAIL\n");
		return -1;
	}

	ret = kpatch_process_mem_read(proc, src, buf, size);
	if (ret > 0)
		ret = kpatch_process_mem_write(proc, buf, dst, size);

	if (ret < 0)
		kpdebug("FAIL\n");
	else
		kpdebug("OK\n");

	free(buf);

	return ret;
}

int
kpatch_ptrace_handle_ld_linux(kpatch_process_t *proc,
			      unsigned long *pentry_point)
{
	/* Wait until we have a first mmap */
	unsigned long orig;
	int ret;
	GElf_Ehdr ehdr;
	struct kpatch_ptrace_ctx *pctx = proc2pctx(proc);

	kpdebug("kpatch_ptrace_handle_ld_linux\n");

	ret = wait_for_mmap(pctx, &orig);
	if (ret == -1) {
		kperr("wait_for_mmap\n");
		return -1;
	}

	ret = kpatch_process_mem_read(proc, orig, &ehdr,
				      sizeof(GElf_Ehdr));
	if (ret == -1) {
		kplogerror("kpatch_ptrace_peek\n");
		return -1;
	}

	*pentry_point = ehdr.e_entry;
	if (ehdr.e_type == ET_DYN)
		*pentry_point += orig;

	kpinfo("ld_linux: orig = %lx, entry_point = %lx\n", orig, *pentry_point);

	return 0;
}

static struct kpatch_ptrace_ctx *
kpatch_ptrace_ctx_alloc(kpatch_process_t *proc)
{
	struct kpatch_ptrace_ctx *p;

	p = malloc(sizeof(*p));
	if (!p)
		return NULL;
	memset(p, 0, sizeof(*p));

	p->execute_until = 0UL;
	p->running = 1;
	p->proc = proc;

	list_init(&p->list);
	list_add(&p->list, &proc->ptrace.pctxs);
	return p;
}

void kpatch_ptrace_ctx_destroy(struct kpatch_ptrace_ctx *pctx)
{
	list_del(&pctx->list);
	free(pctx);
}

int kpatch_ptrace_attach_thread(kpatch_process_t *proc,
				int tid)
{
	long ret;
	int status;
	struct kpatch_ptrace_ctx *pctx;

	pctx = kpatch_ptrace_ctx_alloc(proc);
	if (pctx == NULL) {
		kperr("Can't alloc kpatch_ptrace_ctx");
		return -1;
	}

	pctx->pid = tid;
	kpdebug("Attaching to %d...", pctx->pid);

	ret = ptrace(PTRACE_ATTACH, pctx->pid, NULL, NULL);
	if (ret < 0) {
		kplogerror("can't attach to %d\n", pctx->pid);
		return -1;
	}

	do {
		ret = waitpid(tid, &status, __WALL);
		if (ret < 0) {
			kplogerror("can't wait for thread\n");
			return -1;
		}

		/* We are expecting SIGSTOP */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
			break;

		/* If we got SIGTRAP because we just got out of execve, wait
		 * for the SIGSTOP
		 */
		if (WIFSTOPPED(status))
			status = (WSTOPSIG(status) == SIGTRAP) ? 0 : WSTOPSIG(status);
		else if (WIFSIGNALED(status))
			/* Resend signal */
			status = WTERMSIG(status);


		ret = ptrace(PTRACE_CONT, pctx->pid, NULL,
			     (void *)(uintptr_t)status);
		if (ret < 0) {
			kplogerror("can't cont tracee\n");
			return -1;
		}
	} while (1);

	pctx->running = 0;

	kpdebug("OK\n");
	return 0;
}

int kpatch_ptrace_detach(struct kpatch_ptrace_ctx *pctx)
{
	long ret;

	if (!pctx->pid)
		return 0;
	kpdebug("Detaching from %d...", pctx->pid);
	ret = ptrace(PTRACE_DETACH, pctx->pid, NULL, NULL);
	if (ret < 0) {
		kplogerror("can't detach from %d\n", pctx->pid);
		return -errno;
	}

	kpdebug("OK\n");

	pctx->running = 1;
	pctx->pid = 0;
	return 0;
}
