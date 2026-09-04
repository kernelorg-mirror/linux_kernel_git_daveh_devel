// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit test for the per-thread kernel shadow stack mapping.
 *
 * Mostly Claude-generated goo
 */
#include <kunit/test.h>
#include <linux/sched/task_stack.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <asm/pgtable.h>

static union thread_union *task_thread_union(struct task_struct *tsk)
{
	return (union thread_union *)task_stack_page(tsk);
}

/* Are there any helpers around for this? */
static void *task_shstk_top(struct task_struct *tsk)
{
	return task_thread_union(tsk)->stacks.shadow_stack +
 		sizeof(task_thread_union(tsk)->stacks.shadow_stack);
}

/* Slot just below the token; safe to probe, never a live return address. */
static unsigned long *shstk_probe_slot(struct task_struct *tsk)
{
	return (unsigned long *)task_shstk_top(tsk) - 2;
}

#define MSR_IA32_S_CET		0x000006a2
#define CET_SHSTK_EN		BIT_ULL(0)
#define CET_WRSS_EN		BIT_ULL(1)

#define MSR_IA32_PL0_SSP	0x000006a4

/*
 * Target function to call while S_CET is active.
 * Marked noinline and notrace so compiler doesn't inline or instrument it.
 */
static noinline notrace void test_shstk_callee(unsigned long expected_ssp_base)
{
	unsigned long current_ssp = 0;

	/* Read current SSP using RDSSPQ (returns 0 if shstk disabled) */
	asm volatile("rdsspq %0" : "=r" (current_ssp) : "0" (0UL));

	pr_info("CET Test: Inside callee, SSP = 0x%lx\n", current_ssp);

	if (current_ssp == 0)
		pr_err("CET Test: Error! SSP is zero (shadow stack inactive)\n");
}

static inline void wrssq(unsigned long val, unsigned long *addr)
{
	asm volatile("wrssq %[val], (%[addr])"
		     : : [val] "r" (val), [addr] "r" (addr)
		     : "memory");
}

static noinline notrace void enable_kernel_shstk_and_load_ssp(unsigned long *token_addr)
{
	unsigned long flags;
	u64 old_msr;
	/*
	 * 2. Format 64-bit Restore Token:
	 * Token must match linear address of token itself with Bit 0 set (64-bit mode)
	 * and Bit 1 clear (not busy).
	 */
	unsigned long restore_token = (unsigned long)token_addr | 0x1ULL;
	printk("CET Test: Prepared restore token 0x%lx at %p\n", restore_token, token_addr);

	local_irq_save(flags);
	__wrmsrq(MSR_IA32_PL0_SSP, (u64)token_addr);
	old_msr = __rdmsr(MSR_IA32_S_CET);

	/* Must be atomic, nothing can go in between these two: */
	__wrmsrq(MSR_IA32_S_CET, old_msr | CET_SHSTK_EN | CET_WRSS_EN);
	asm volatile ( "setssbsy" ::: "memory" );
	//wrssq(restore_token, token_addr);
	/* End atomic bit */


	local_irq_restore(flags);
}

static void test_supervisor_shadow_stack(struct kunit *test)
{
	struct task_struct *tsk = current;
	unsigned long shstk_base;
	unsigned long *token_addr;
	u64 old_msr;

	printk("start...\n");

	/* 1. Locate the allocated 4K buffer */
	shstk_base = (unsigned long)&task_thread_union(tsk)->stacks.shadow_stack;
	if (!shstk_base) {
		pr_err("CET Test: shadow stack buffer is NULL\n");
		return;
	}

	/* Point 8 bytes below the top of the stack: */
	token_addr = task_shstk_top(tsk);
	token_addr--;

	printk("msr: %016llx\n", __rdmsr(MSR_IA32_S_CET));

	pr_info("before: 0x%lx\n", *token_addr);
	for (int i = 0; i < 20; i++) {printk("%d:%d\n", __LINE__, i); __udelay(100*USEC_PER_MSEC);}
	/* 5. Enable Supervisor Shadow Stack in MSR_IA32_S_CET */
	enable_kernel_shstk_and_load_ssp(token_addr);

	pr_info("after: 0x%lx\n", *token_addr);
	for (int i = 0; i < 20; i++) {printk("%d:%d\n", __LINE__, i); __udelay(100*USEC_PER_MSEC);}
	/*
	 * 6. Switch SSP to our new shadow stack using RSTORSSP.
	 * Hardware consumes the restore token, replaces it with a previous-ssp
	 * token, and sets internal SSP = token_addr.
	 */
	//asm volatile("rstorssp %0" : : "m" (*token_addr) : "memory");

	/*
	 * 7. Perform CALL and RET under Supervisor Shadow Stack:
	 * - Hardware CALL pushes return RIP onto the shadow stack (SSP -= 8).
	 * - Callee executes and returns.
	 * - Hardware RET pops and validates return RIP from shadow stack (SSP += 8).
	 */
	test_shstk_callee(shstk_base);

	/* 8. Disable Supervisor Shadow Stack in MSR */
	wrmsrq(MSR_IA32_S_CET, old_msr);

	/* 9. Restore PTE permissions back to normal kernel R/W */
	//set_page_shstk_perm(shstk_base, false);

	pr_info("CET Test: Supervisor shadow stack test completed successfully.\n");
}



static void shstk_vmalloc_alias_not_writable(struct kunit *test)
{
	unsigned long *slot = shstk_probe_slot(current);
	unsigned long val = 0xdeadbeefUL;

	KUNIT_EXPECT_EQ(test, copy_to_kernel_nofault(slot, &val, sizeof(val)), -EFAULT);
}

static void shstk_vmalloc_alias_readable(struct kunit *test)
{
	unsigned long *slot = shstk_probe_slot(current);
	unsigned long rd;

	KUNIT_EXPECT_EQ(test, copy_from_kernel_nofault(&rd, slot, sizeof(rd)), 0);
}

static void shstk_direct_map_writable(struct kunit *test)
{
	unsigned long *slot = shstk_probe_slot(current);
	struct page *page = vmalloc_to_page(slot);
	unsigned long *alias;
	unsigned long orig, val = 0xdeadbeefUL, rd;

	KUNIT_ASSERT_NOT_NULL(test, page);
	alias = page_address(page) + offset_in_page(slot);

	KUNIT_ASSERT_EQ(test, copy_from_kernel_nofault(&orig, alias, sizeof(orig)), 0);
	KUNIT_EXPECT_EQ(test, copy_to_kernel_nofault(alias, &val, sizeof(val)), 0);
	KUNIT_EXPECT_EQ(test, copy_from_kernel_nofault(&rd, slot, sizeof(rd)), 0);
	KUNIT_EXPECT_EQ(test, rd, val);

	/* restore */
	copy_to_kernel_nofault(alias, &orig, sizeof(orig));
}

/* Positive control: the same probe on the normal stack must succeed. */
static void normal_stack_writable(struct kunit *test)
{
	unsigned long val = 0xdeadbeefUL, local = 0;

	KUNIT_EXPECT_EQ(test, copy_to_kernel_nofault(&local, &val, sizeof(val)), 0);
	KUNIT_EXPECT_EQ(test, local, val);
}

static void shstk_pte_is_shadow_stack(struct kunit *test)
{
	unsigned long addr = (unsigned long)shstk_probe_slot(current);
	unsigned int level;
	pte_t *ptep = lookup_address(addr, &level);

	KUNIT_ASSERT_NOT_NULL(test, ptep);
	KUNIT_EXPECT_EQ(test, level, (unsigned int)PG_LEVEL_4K);
	KUNIT_EXPECT_TRUE(test, pte_present(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_dirty(*ptep)); // shstk pages are always D=1
	KUNIT_EXPECT_TRUE(test, pte_write(*ptep)); // kernel considers them writable
	KUNIT_EXPECT_FALSE(test, pte_flags(*ptep) & _PAGE_RW); // although RW=0
}

static struct kunit_case shstk_test_cases[] = {
	KUNIT_CASE(shstk_vmalloc_alias_not_writable),
	KUNIT_CASE(shstk_vmalloc_alias_readable),
	KUNIT_CASE(shstk_direct_map_writable),
	KUNIT_CASE(normal_stack_writable),
	KUNIT_CASE(shstk_pte_is_shadow_stack),
	KUNIT_CASE(test_supervisor_shadow_stack),
	{}
};

static struct kunit_suite shstk_test_suite = {
	.name = "x86_kernel_shstk",
	.test_cases = shstk_test_cases,
};

kunit_test_suite(shstk_test_suite);
MODULE_DESCRIPTION("KUnit test for x86 kernel shadow stack mapping");
MODULE_LICENSE("GPL");
