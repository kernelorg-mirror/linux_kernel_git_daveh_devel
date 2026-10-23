// SPDX-License-Identifier: GPL-2.0

#include <linux/ptrace.h>
#include <asm/bugs.h>
#include <asm/msr.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/insn-eval.h>
#include <asm/special_insns.h>
#include <asm/set_memory.h>

enum cp_error_code {
	CP_EC        = (1 << 15) - 1,

	CP_RET       = 1,
	CP_IRET      = 2,
	CP_ENDBR     = 3,
	CP_RSTRORSSP = 4,
	CP_SETSSBSY  = 5,

	CP_ENCL	     = 1 << 15,
};

static const char cp_err[][10] = {
	[0] = "unknown",
	[1] = "near ret",
	[2] = "far/iret",
	[3] = "endbranch",
	[4] = "rstorssp",
	[5] = "setssbsy",
};

static const char *cp_err_string(unsigned long error_code)
{
	unsigned int cpec = error_code & CP_EC;

	if (cpec >= ARRAY_SIZE(cp_err))
		cpec = 0;
	return cp_err[cpec];
}

static void do_unexpected_cp(struct pt_regs *regs, unsigned long error_code)
{
	WARN_ONCE(1, "Unexpected %s #CP, error_code: %s\n",
		  user_mode(regs) ? "user mode" : "kernel mode",
		  cp_err_string(error_code));
}

static DEFINE_RATELIMIT_STATE(cpf_rate, DEFAULT_RATELIMIT_INTERVAL,
			      DEFAULT_RATELIMIT_BURST);

static void do_user_cp_fault(struct pt_regs *regs, unsigned long error_code)
{
	struct task_struct *tsk;
	unsigned long ssp;

	/*
	 * An exception was just taken from userspace. Since interrupts are disabled
	 * here, no scheduling should have messed with the registers yet and they
	 * will be whatever is live in userspace. So read the SSP before enabling
	 * interrupts so locking the fpregs to do it later is not required.
	 */
	rdmsrq(MSR_IA32_PL3_SSP, ssp);

	cond_local_irq_enable(regs);

	tsk = current;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = X86_TRAP_CP;

	/* Ratelimit to prevent log spamming. */
	if (show_unhandled_signals && unhandled_signal(tsk, SIGSEGV) &&
	    __ratelimit(&cpf_rate)) {
		pr_emerg("%s[%d] control protection ip:%lx sp:%lx ssp:%lx error:%lx(%s)%s",
			 tsk->comm, task_pid_nr(tsk),
			 regs->ip, regs->sp, ssp, error_code,
			 cp_err_string(error_code),
			 error_code & CP_ENCL ? " in enclave" : "");
		print_vma_addr(KERN_CONT " in ", regs->ip);
		pr_cont("\n");
	}

	force_sig_fault(SIGSEGV, SEGV_CPERR, (void __user *)0);
	cond_local_irq_disable(regs);
}

static __ro_after_init bool ibt_fatal = true;

/*
 * By definition, all missing-ENDBRANCH #CPs are a result of WFE && !ENDBR.
 *
 * For the kernel IBT no ENDBR selftest where #CPs are deliberately triggered,
 * the WFE state of the interrupted context needs to be cleared to let execution
 * continue.  Otherwise when the CPU resumes from the instruction that just
 * caused the previous #CP, another missing-ENDBRANCH #CP is raised and the CPU
 * enters a dead loop.
 *
 * This is not a problem with IDT because it doesn't preserve WFE and IRET doesn't
 * set WFE.  But FRED provides space on the entry stack (in an expanded CS area)
 * to save and restore the WFE state, thus the WFE state is no longer clobbered,
 * so software must clear it.
 */
static void ibt_clear_fred_wfe(struct pt_regs *regs)
{
	/*
	 * No need to do any FRED checks.
	 *
	 * For IDT event delivery, the high-order 48 bits of CS are pushed
	 * as 0s into the stack, and later IRET ignores these bits.
	 *
	 * For FRED, a test to check if fred_cs.wfe is set would be dropped
	 * by compilers.
	 */
	regs->fred_cs.wfe = 0;
}

static void do_kernel_cp_fault(struct pt_regs *regs, unsigned long error_code)
{
	if ((error_code & CP_EC) != CP_ENDBR) {
		do_unexpected_cp(regs, error_code);
		return;
	}

	if (unlikely(regs->ip == (unsigned long)&ibt_selftest_noendbr)) {
		regs->ax = 0;
		ibt_clear_fred_wfe(regs);
		return;
	}

	pr_err("Missing ENDBR: %pS\n", (void *)instruction_pointer(regs));
	if (!ibt_fatal) {
		printk(KERN_DEFAULT CUT_HERE);
		__warn(__FILE__, __LINE__, (void *)regs->ip, TAINT_WARN, regs, NULL);
		ibt_clear_fred_wfe(regs);
		return;
	}
	BUG();
}

static int __init ibt_setup(char *str)
{
	if (!strcmp(str, "off"))
		setup_clear_cpu_cap(X86_FEATURE_IBT);

	if (!strcmp(str, "warn"))
		ibt_fatal = false;

	return 1;
}

__setup("ibt=", ibt_setup);

DEFINE_IDTENTRY_ERRORCODE(exc_control_protection)
{
	if (user_mode(regs)) {
		if (cpu_feature_enabled(X86_FEATURE_USER_SHSTK))
			do_user_cp_fault(regs, error_code);
		else
			do_unexpected_cp(regs, error_code);
	} else {
		if (cpu_feature_enabled(X86_FEATURE_IBT))
			do_kernel_cp_fault(regs, error_code);
		else
			do_unexpected_cp(regs, error_code);
	}
}

/*
 * FRED hardware pushes this frame on to the shadow stack for
 * kernel=>kernel entry. First (lowest address) in this struct
 * is the last entry pushed by the hardware.
 */
struct fred_shstk_entry_frame {
	u64 ssef_ssp;
	u64 ssef_lip;
	u64 ssef_cs;
};

/*
 * The kernel=>kernel entry code pushes SSP on to the entry stack.
 * This only occurs for kernel=>kernel entry. Not userspace.
 *
 * SSP is pushed on to the frame below pt_regs. At the point it is
 * pushed, it points to a special FRED entry frame.
 */
struct fred_kernel_frame {
	struct fred_shstk_entry_frame *ssef;
	struct pt_regs regs;
};

/*
 * Change the return IP of an event. Use this instead of directly
 * manipulating regs->ip.
 *
 * The hardware saves a special FRED entry frame on to the shadow
 * stack. It contains the RIP of the interrupted context. ERETS
 * ensures that this matches regs->ip.
 *
 * Update the FRED entry frame in addition to regs->ip.
 */
void regs_set_return_ip(struct pt_regs *regs, unsigned long ip)
{
	struct fred_shstk_entry_frame *ssef;

	regs->ip = ip;

	if (!cpu_feature_enabled(X86_FEATURE_KERN_SHSTK))
		return;

	/* Only kernel-mode events save the 'ssef' pointer. */
	WARN_ON_ONCE(user_mode(regs));

	ssef = container_of(regs, struct fred_kernel_frame, regs)->ssef;
	if (!ssef)
		return;

	wrss(ip, &ssef->ssef_lip);
}

static inline void *task_shadow_stack(struct task_struct *task)
{
	return &task_thread_union(current)->stacks.shadow_stack[0];
}

static inline unsigned long shadow_stack_size(void)
{
	return sizeof(task_thread_union(current)->stacks.shadow_stack);
}

static inline unsigned long *task_shstk_slot(int nr)
{
	unsigned long *top = task_shstk_top(current);

	return &top[-1 - nr];
}

static unsigned long *shstk_alias(unsigned long *addr)
{
	struct page *page;

	/* Most shadow stacks are vmap'd: */
	page = vmalloc_to_page(addr);
	/* init_task is not a vmalloc address */
	if (!is_vmalloc_addr(addr))
		page = virt_to_page(addr);

	return page_address(page) + offset_in_page(addr);
}

static void shstk_create_restore_token(unsigned long *ro_slot)
{
	unsigned long *rw_slot = shstk_alias(ro_slot);
	unsigned long restore_token;

	/*
	 * The token value is based on the actual read-only shadow
	 * stack address, but points one slot *above* itself:
	 */
	restore_token = (unsigned long)(ro_slot + 1) | SHSTK_TOKEN_MODE64;

	/* Write the token to the r/w alias: */
	*rw_slot = restore_token;
}

#define KSHSTK_MAX_ENTS 64

/*
 * Use the unwinder infrastructure to walk back up the regular stack
 * and mirror all the return addresses over to the shadow stack.
 *
 * root_sp is captured in assembly before calling here to prevent the
 * compiler from messing with it. There may be additional frames or
 * other gunk on the stack below root_sp by the time the unwinder
 * starts, but those will ignored. All that matters is that the stack
 * is back to "root_sp" when shadow stacks are enabled.
 */
asmlinkage void kshstk_build(unsigned long *root_sp)
{
	unsigned long ents[KSHSTK_MAX_ENTS];
	struct unwind_state state;
	unsigned long *ro_slot;
	unsigned long *rw_slot;
	int n = 0;

	/*
	 * Use the unwinder to find the return addresses of callers.
	 * Note that ents[0] is the most recent call. The is the
	 * opposite of stacks. ents[] is tempoarary "upside down"
	 * storage that will be reversed when copied to the shadow
	 * stack.
	 */
	for (unwind_start(&state, current, NULL, root_sp);
	     !unwind_done(&state) && n < KSHSTK_MAX_ENTS;
	     unwind_next_frame(&state))
		ents[n++] = unwind_get_return_address(&state);

	BUG_ON(n == KSHSTK_MAX_ENTS);

	/* Transfer the return addresses to the shadow stack: */
	ro_slot = task_shstk_slot(0);
	rw_slot = shstk_alias(ro_slot);
	for (int i = n - 1; i >= 0; i--) {
		*rw_slot = ents[i];
		rw_slot--;
		ro_slot--;
	}
	/* Put a restore token in the last slot: */
	shstk_create_restore_token(ro_slot);
}

static void kshstk_prepare_pages(void)
{
	/*
	 * Necessary for the init_task shadow stack on the boot CPU,
	 * but not the secondary CPUs which have normal vmap'd stacks.
	 */
	set_memory_shstk_noalias((unsigned long)task_shadow_stack(current),
				 shadow_stack_size() / PAGE_SIZE);
}

/*
 * This "locks" the stack in place and does not allow any control
 * flow manipulation to occur because of changes to the stack.
 *
 * CPU enters with shadow stacks disabled and leaves with them
 * enabled.
 *
 * Must be called before the CPU does its first context switch.
 */
void arch_kernel_stack_lock_current(void)
{
	unsigned long flags;

	if (!cpu_feature_enabled(X86_FEATURE_KERN_SHSTK))
		return;

	kshstk_prepare_pages();

	/*
	 * Regular interrupts are delivered on stack level 0. There
	 * is a window within the enabling where CET_SHSTK_EN=1 but
	 * SSP is not yet set. If an interrupt is delivered in that
	 * window, it would try to push on to this stack. Disable
	 * regular interrupts over this window.
	 *
	 * Interrupts that use other stack levels (like NMI) are OK
	 * because FRED switches stacks for them and does not push
	 * on stack level 0.
	 */
	local_irq_save(flags);
	current->thread.kshstk_ssp = kshstk_enable_current();
	local_irq_restore(flags);
}
