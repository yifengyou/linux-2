/* thread_info.h: i386 low-level thread information
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds and Dave Miller
 */

#ifndef _ASM_THREAD_INFO_H
#define _ASM_THREAD_INFO_H

#ifdef __KERNEL__

#include <linux/compiler.h>
#include <asm/page.h>

#ifndef __ASSEMBLY__
#include <asm/processor.h>
#endif

/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - this struct shares the supervisor stack pages
 * - if the contents of this structure are changed,
 *   the assembly constants must also be changed
 */
#ifndef __ASSEMBLY__

struct thread_info {
	struct task_struct	*task;		/* main task structure */
	struct exec_domain	*exec_domain;	/* execution domain */
	unsigned long		flags;		/* low level flags */
	unsigned long		status;		/* thread-synchronous flags */
	__u32			cpu;		/* current CPU */
	int			preempt_count;	/* 0 => preemptable,
						   <0 => BUG */
	mm_segment_t		addr_limit;	/* thread address space:
						   0-0xBFFFFFFF user-thread
						   0-0xFFFFFFFF kernel-thread
						*/
	void			*sysenter_return;
	struct restart_block    restart_block;
	unsigned long           previous_esp;   /* ESP of the previous stack in
						   case of nested (IRQ) stacks
						*/
	__u8			supervisor_stack[0];
};

#else /* !__ASSEMBLY__ */

#include <asm/asm-offsets.h>

#endif

#define PREEMPT_ACTIVE		0x10000000
#ifdef CONFIG_4KSTACKS
#define THREAD_SIZE            (4096)
#else
#define THREAD_SIZE		(8192)
#endif

#define STACK_WARN             (THREAD_SIZE/8)
/*
 * macros/functions for gaining access to the thread information structure
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#ifndef __ASSEMBLY__

#define INIT_THREAD_INFO(tsk)			\
{						\
	.task		= &tsk,			\
	.exec_domain	= &default_exec_domain,	\
	.flags		= 0,			\
	.cpu		= 0,			\
	.preempt_count	= 1,			\
	.addr_limit	= KERNEL_DS,		\
	.restart_block = {			\
		.fn = do_no_restart_syscall,	\
	},					\
}

#define init_thread_info	(init_thread_union.thread_info)
#define init_stack		(init_thread_union.stack)


/* how to get the current stack pointer from C */
register unsigned long current_stack_pointer asm("esp") __used;

/* how to get the thread information struct from C */
static inline struct thread_info *current_thread_info(void)
{
	return (struct thread_info *)
		(current_stack_pointer & ~(THREAD_SIZE - 1));
}

/* thread information allocation */
#ifdef CONFIG_DEBUG_STACK_USAGE
#define alloc_thread_info(tsk) ((struct thread_info *)			\
	__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(THREAD_SIZE)))
#else
#define alloc_thread_info(tsk) ((struct thread_info *)			\
	__get_free_pages(GFP_KERNEL, get_order(THREAD_SIZE)))
#endif

#else /* !__ASSEMBLY__ */

/* how to get the thread information struct from ASM */
#define GET_THREAD_INFO(reg)	 \
	movl $-THREAD_SIZE, reg; \
	andl %esp, reg

/* use this one if reg already contains %esp */
#define GET_THREAD_INFO_WITH_ESP(reg) \
	andl $-THREAD_SIZE, reg

#endif

/*
 * thread information flags
 * - these are process state flags that various
 *   assembly files may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 */
#define TIF_SYSCALL_TRACE	0	/* syscall trace active */
#define TIF_SIGPENDING		1	/* signal pending */
#define TIF_NEED_RESCHED	2	/* rescheduling necessary */
#define TIF_SINGLESTEP		3	/* restore singlestep on return to
					   user mode */
#define TIF_IRET		4	/* return with iret */
#define TIF_SYSCALL_EMU		5	/* syscall emulation active */
#define TIF_SYSCALL_AUDIT	6	/* syscall auditing active */
#define TIF_SECCOMP		7	/* secure computing */
#define TIF_HRTICK_RESCHED	9	/* reprogram hrtick timer */
#define TIF_MEMDIE		16
#define TIF_DEBUG		17	/* uses debug registers */
#define TIF_IO_BITMAP		18	/* uses I/O bitmap */
#define TIF_FREEZE		19	/* is freezing for suspend */
#define TIF_NOTSC		20	/* TSC is not accessible in userland */
#define TIF_FORCED_TF		21	/* true if TF in eflags artificially */
#define TIF_DEBUGCTLMSR		22	/* uses thread_struct.debugctlmsr */
#define TIF_DS_AREA_MSR 	23      /* uses thread_struct.ds_area_msr */
#define TIF_BTS_TRACE_TS        24      /* record scheduling event timestamps */

#define _TIF_SYSCALL_TRACE	(1 << TIF_SYSCALL_TRACE)
#define _TIF_SIGPENDING		(1 << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED	(1 << TIF_NEED_RESCHED)
#define _TIF_SINGLESTEP		(1 << TIF_SINGLESTEP)
#define _TIF_IRET		(1 << TIF_IRET)
#define _TIF_SYSCALL_EMU	(1 << TIF_SYSCALL_EMU)
#define _TIF_SYSCALL_AUDIT	(1 << TIF_SYSCALL_AUDIT)
#define _TIF_SECCOMP		(1 << TIF_SECCOMP)
#define _TIF_HRTICK_RESCHED	(1 << TIF_HRTICK_RESCHED)
#define _TIF_DEBUG		(1 << TIF_DEBUG)
#define _TIF_IO_BITMAP		(1 << TIF_IO_BITMAP)
#define _TIF_FREEZE		(1 << TIF_FREEZE)
#define _TIF_NOTSC		(1 << TIF_NOTSC)
#define _TIF_FORCED_TF		(1 << TIF_FORCED_TF)
#define _TIF_DEBUGCTLMSR	(1 << TIF_DEBUGCTLMSR)
#define _TIF_DS_AREA_MSR	(1 << TIF_DS_AREA_MSR)
#define _TIF_BTS_TRACE_TS	(1 << TIF_BTS_TRACE_TS)

/* work to do on interrupt/exception return */
#define _TIF_WORK_MASK							\
	(0x0000FFFF & ~(_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT |	\
			_TIF_SECCOMP | _TIF_SYSCALL_EMU))
/* work to do on any return to u-space */
#define _TIF_ALLWORK_MASK	(0x0000FFFF & ~_TIF_SECCOMP)

/* flags to check in __switch_to() */
#define _TIF_WORK_CTXSW						\
	(_TIF_IO_BITMAP | _TIF_NOTSC | _TIF_DEBUGCTLMSR |	\
	 _TIF_DS_AREA_MSR | _TIF_BTS_TRACE_TS)
#define _TIF_WORK_CTXSW_PREV _TIF_WORK_CTXSW
#define _TIF_WORK_CTXSW_NEXT (_TIF_WORK_CTXSW | _TIF_DEBUG)


/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_USEDFPU		0x0001	/* FPU was used by this task
					   this quantum (SMP) */
#define TS_POLLING		0x0002	/* True if in idle loop
					   and not sleeping */
#define TS_RESTORE_SIGMASK	0x0004	/* restore signal mask in do_signal() */

#define tsk_is_polling(t) (task_thread_info(t)->status & TS_POLLING)

#ifndef __ASSEMBLY__
#define HAVE_SET_RESTORE_SIGMASK	1
static inline void set_restore_sigmask(void)
{
	struct thread_info *ti = current_thread_info();
	ti->status |= TS_RESTORE_SIGMASK;
	set_bit(TIF_SIGPENDING, &ti->flags);
}
#endif	/* !__ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_THREAD_INFO_H */
