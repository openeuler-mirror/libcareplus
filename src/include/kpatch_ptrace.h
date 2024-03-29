/******************************************************************************
 * 2021.10.11 - kpatch_ptrace: fix x86 compile warning
 * Huawei Technologies Co., Ltd. <zhengchuan@huawei.com>
 *
 * 2021.10.08 - ptrace/process/patch: fix some bad code problem
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 ******************************************************************************/

#ifndef __KPATCH_PTRACE_H__
#define __KPATCH_PTRACE_H__

#include <sys/user.h>
#ifdef __riscv
#include <asm/ptrace.h>
#endif
#include "list.h"

struct kpatch_ptrace_ctx {
	int pid;
	int running;
	unsigned long execute_until;
	kpatch_process_t *proc;
	struct list_head list;
};

struct process_mem_iter {
	kpatch_process_t *proc;
	unsigned long base;
	size_t buflen;
	size_t buffer_size;
	char buffer[];
};

struct process_mem_iter *
kpatch_process_mem_iter_init(kpatch_process_t *proc);
void kpatch_process_mem_iter_free(struct process_mem_iter *iter);
int kpatch_process_mem_iter_peek_ulong(struct process_mem_iter *iter,
									   unsigned long *dst,
									   unsigned long remote_addr);
int kpatch_process_mem_iter_peek(struct process_mem_iter *iter,
				 void *dst, size_t size,
				 unsigned long remote_addr);

#define REMOTE_PEEK(iter, dst, remote_addr) \
	kpatch_process_mem_iter_peek((iter), &(dst), sizeof(dst),	\
				     (unsigned long)(remote_addr))

#define PEEK_ULONG(p) ({						\
	unsigned long l;						\
	if (kpatch_process_mem_iter_peek_ulong(iter, &l,		\
					       (unsigned long)(p)) < 0) {\
		kpdebug("FAIL. Failed to peek at 0x%lx - %s\n",		\
			(unsigned long)(p), strerror(errno));		\
		return -1;						\
	}								\
	l;								\
})


void kpatch_ptrace_ctx_destroy(struct kpatch_ptrace_ctx *pctx);

int kpatch_ptrace_attach_thread(kpatch_process_t *proc, int tid);
int kpatch_ptrace_detach(struct kpatch_ptrace_ctx *pctx);

int kpatch_ptrace_handle_ld_linux(kpatch_process_t *proc,
				  unsigned long *pentry_point);


int wait_for_stop(struct kpatch_ptrace_ctx *pctx, const void *data);
int get_threadgroup_id(int tid);
int kpatch_arch_ptrace_kickstart_execve_wrapper(kpatch_process_t *proc);
int kpatch_ptrace_get_entry_point(struct kpatch_ptrace_ctx *pctx,
				  unsigned long *pentry_point);

#define EXECUTE_ALL_THREADS	(1 << 0) /* execute all threads not just these
					    having non-zero execute_until */
int kpatch_ptrace_execute_until(kpatch_process_t *proc,
				int timeout_msec,
				unsigned int flags);

int kpatch_execute_remote(struct kpatch_ptrace_ctx *pctx,
			  const unsigned char *code,
			  size_t codelen,
			  struct user_regs_struct *pregs);

int kpatch_arch_ptrace_resolve_ifunc(struct kpatch_ptrace_ctx *pctx,
				unsigned long *addr);
unsigned long
kpatch_mmap_remote(struct kpatch_ptrace_ctx *pctx,
		   unsigned long addr,
		   size_t length,
		   int prot,
		   int flags,
		   int fd,
		   off_t offset);

int
kpatch_mprotect_remote(struct kpatch_ptrace_ctx *pctx,
		       unsigned long addr,
		       size_t length,
		       int prot);

int
kpatch_munmap_remote(struct kpatch_ptrace_ctx *pctx,
		     unsigned long addr,
		     size_t length);

#define MAX_ERRNO	4095
int kpatch_arch_prctl_remote(struct kpatch_ptrace_ctx *pctx, int code, unsigned long *addr);

int
kpatch_process_mem_read(kpatch_process_t *proc,
			unsigned long src,
			void *dst,
			size_t size);
int
kpatch_process_mem_write(kpatch_process_t *proc,
			 void *src,
			 unsigned long dst,
			 size_t size);

int
kpatch_process_memcpy(kpatch_process_t *proc,
		      unsigned long dst,
		      unsigned long src,
		      size_t size);

#ifdef __riscv
#define BREAK_INSN_LENGTH	4
#define BREAK_INSN		{ 0x73, 0x00, 0x10, 0x00 }
#else
#define BREAK_INSN_LENGTH	1
#define BREAK_INSN		{0xcc}
#endif

#define SEC_TO_MSEC	1000
#define MSEC_TO_NSEC	1000000

#define for_each_thread(proc, pctx)	\
	list_for_each_entry(pctx, &proc->ptrace.pctxs, list)

struct kpatch_ptrace_ctx *
kpatch_ptrace_find_thread(kpatch_process_t *proc,
			  pid_t pid,
			  unsigned long rip);

int
kpatch_arch_ptrace_waitpid(kpatch_process_t *proc,
		      struct timespec *timeout,
		      const sigset_t *sigset);

void copy_regs(struct user_regs_struct *dst,
		      struct user_regs_struct *src);

int
kpatch_arch_execute_remote_func(struct kpatch_ptrace_ctx *pctx,
			   const unsigned char *code,
			   size_t codelen,
			   struct user_regs_struct *pregs,
			   int (*func)(struct kpatch_ptrace_ctx *pctx, const void *data),
			   const void *data);

int kpatch_arch_syscall_remote(struct kpatch_ptrace_ctx *pctx, int nr,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5, unsigned long arg6,
		unsigned long *res);

int wait_for_mmap(struct kpatch_ptrace_ctx *pctx,
	      unsigned long *pbase);

#endif
