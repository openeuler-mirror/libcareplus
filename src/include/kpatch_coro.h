#ifndef __KPATCH_CORO__
#define __KPATCH_CORO__

#include <setjmp.h>

#include "list.h"

struct kpatch_process;

struct kpatch_coro_ops {
	int (*find_coroutines)(struct kpatch_process *proc);
};

struct kpatch_coro {
	struct list_head list;
	sigjmp_buf env;
};

void *_UCORO_create(struct kpatch_coro *coro, pid_t pid);
void _UCORO_destroy(void *arg);


struct UCORO_info {
	union {
		void *upt;
		char dummy[256];
	};
	struct kpatch_coro *coro;
};
int _UCORO_access_reg(unw_addr_space_t as, unw_regnum_t reg,
					unw_word_t *val, int write, void *arg);

#define PTR_DEMANGLE(ptr, key) ((((ptr) >> 0x11) | ((ptr) << 47)) ^ key)
#define JB_RBX 0
#define JB_RBP 1
#define JB_R12 2
#define JB_R13 3
#define JB_R14 4
#define JB_R15 5
#define JB_RSP 6
#define JB_RIP 7

#define STACK_OFFSET_UC_LINK (2 * sizeof(long))
#define STACK_OFFSET_START_CONTEXT (3 * sizeof(long))
#define STACK_OFFSET_UC_LINK_PTR (4 * sizeof(long))
#define STACK_OFFSET_COROUTINE_UCONTEXT (7 * sizeof(long))
#define STACK_OFFSET_COROUTINE (8 * sizeof(long))

#define UCONTEXT_OFFSET_JMPBUF 0x38

#define GLIBC_TLS_PTR_GUARD 0x30
int get_ptr_guard(struct kpatch_process *proc,
					unsigned long *ptr_guard);

int locate_start_context_symbol(struct kpatch_process *proc,
					unsigned long *pstart_context);


int kpatch_coroutines_init(struct kpatch_process *proc);
int kpatch_coroutines_find(struct kpatch_process *proc);
void kpatch_coroutines_free(struct kpatch_process *proc);

#endif
