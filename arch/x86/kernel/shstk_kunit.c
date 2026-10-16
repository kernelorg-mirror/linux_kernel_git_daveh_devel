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
	{}
};

static struct kunit_suite shstk_test_suite = {
	.name = "x86_kernel_shstk",
	.test_cases = shstk_test_cases,
};

kunit_test_suite(shstk_test_suite);
MODULE_DESCRIPTION("KUnit test for x86 kernel shadow stack mapping");
MODULE_LICENSE("GPL");
