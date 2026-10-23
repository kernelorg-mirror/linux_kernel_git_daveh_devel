/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SHSTK_H
#define _ASM_X86_SHSTK_H

#define SHSTK_TOKEN_MODE64	BIT_ULL(0) /* Token created in 64-bit mode */
#define SHSTK_TOKEN_TYPE	BIT_ULL(1) /* Types: Restore: 0, Prev-SSP: 1 */

#ifndef __ASSEMBLER__
#include <linux/types.h>

struct task_struct;
struct ksignal;

#ifdef CONFIG_X86_USER_SHADOW_STACK
struct thread_shstk {
	u64	base;
	u64	size;
};

long shstk_prctl(struct task_struct *task, int option, unsigned long arg2);
void reset_thread_features(void);
unsigned long shstk_alloc_thread_stack(struct task_struct *p, u64 clone_flags,
				       unsigned long stack_size);
void shstk_free(struct task_struct *p);
int setup_signal_shadow_stack(struct ksignal *ksig);
int restore_signal_shadow_stack(void);
int shstk_update_last_frame(unsigned long val);
bool shstk_is_enabled(void);
int shstk_pop(u64 *val);
int shstk_push(u64 val);

asmlinkage __visible void kshstk_build(unsigned long *);
void arch_kernel_stack_lock_current(void);
void *kshstk_enable_current(void);
#else
static inline long shstk_prctl(struct task_struct *task, int option,
			       unsigned long arg2) { return -EINVAL; }
static inline void reset_thread_features(void) {}
static inline unsigned long shstk_alloc_thread_stack(struct task_struct *p,
						     u64 clone_flags,
						     unsigned long stack_size) { return 0; }
static inline void shstk_free(struct task_struct *p) {}
static inline int setup_signal_shadow_stack(struct ksignal *ksig) { return 0; }
static inline int restore_signal_shadow_stack(void) { return 0; }
static inline int shstk_update_last_frame(unsigned long val) { return 0; }
static inline bool shstk_is_enabled(void) { return false; }
static inline int shstk_pop(u64 *val) { return -ENOTSUPP; }
static inline int shstk_push(u64 val) { return -ENOTSUPP; }
static inline void arch_kernel_stack_lock_current(void) {}
#endif /* CONFIG_X86_USER_SHADOW_STACK */

#endif /* __ASSEMBLER__ */

#endif /* _ASM_X86_SHSTK_H */
