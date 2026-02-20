/*
 * Copyright (c) 2013-2025, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <platform_def.h>

#include <arch.h>
#include <common/bl_common.h>
#include <el3_common_macros.S>
#include <lib/pmf/aarch64/pmf_asm_macros.S>
#include <lib/runtime_instr.h>
#include <lib/xlat_tables/xlat_mmu_helpers.h>

	.globl	bl31_entrypoint
	.globl	bl31_warm_entrypoint

	/* -----------------------------------------------------
	 * bl31_entrypoint() 是冷启动入口点，
	 * 仅由主CPU执行。
	 * -----------------------------------------------------
	 */
func bl31_entrypoint
	/* ---------------------------------------------------------------
	 * 保存前一个引导加载程序的参数 x0 - x3 以供后续使用。
	 * ---------------------------------------------------------------
	 */
	mov	x20, x0
	mov	x21, x1
	mov	x22, x2
	mov	x23, x3

#if !RESET_TO_BL31
	/* ---------------------------------------------------------------------
	 * 对于 !RESET_TO_BL31 系统，只有主CPU在冷启动流程中会到达
	 * bl31_entrypoint()，因此在这种情况下不应执行冷/热启动以及
	 * 主/从CPU逻辑。
	 *
	 * 同时假设前一个引导加载程序已经初始化了 SCTLR_EL3（包括字节序），
	 * 并且已初始化内存。
	 * ---------------------------------------------------------------------
	 */
	el3_entrypoint_common					\
		_init_sctlr=0					\
		_warm_boot_mailbox=0				\
		_secondary_cold_boot=0				\
		_init_memory=0					\
		_init_c_runtime=1				\
		_exception_vectors=runtime_exceptions		\
		_pie_fixup_size=BL31_LIMIT - BL31_BASE
#else

	/* ---------------------------------------------------------------------
	 * 对于具有可编程复位地址的 RESET_TO_BL31 系统，
	 * bl31_entrypoint() 仅在冷启动路径上执行，因此可以跳过
	 * 热启动邮箱机制。
	 * ---------------------------------------------------------------------
	 */
	el3_entrypoint_common					\
		_init_sctlr=1					\
		_warm_boot_mailbox=!PROGRAMMABLE_RESET_ADDRESS	\
		_secondary_cold_boot=!COLD_BOOT_SINGLE_CPU	\
		_init_memory=1					\
		_init_c_runtime=1				\
		_exception_vectors=runtime_exceptions		\
		_pie_fixup_size=BL31_LIMIT - BL31_BASE
#endif /* RESET_TO_BL31 */

	/* --------------------------------------------------------------------
	 * 执行 BL31 设置
	 * --------------------------------------------------------------------
	 */
	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23

	/* --------------------------------------------------------------------
	 * 跳转到主函数
	 * --------------------------------------------------------------------
	 */
	bl	bl31_main

	/* --------------------------------------------------------------------
	 * 将 .data 和 .bss 段清理到主内存。这确保了主CPU初始化的任何全局数据
	 * 在从CPU启用其数据缓存并参与一致性之前对其可见。
	 * --------------------------------------------------------------------
	 */
	adrp	x0, __DATA_START__
	add	x0, x0, :lo12:__DATA_START__
	adrp	x1, __DATA_END__
	add	x1, x1, :lo12:__DATA_END__
	sub	x1, x1, x0
	bl	clean_dcache_range

	adrp	x0, __BSS_START__
	add	x0, x0, :lo12:__BSS_START__
	adrp	x1, __BSS_END__
	add	x1, x1, :lo12:__BSS_END__
	sub	x1, x1, x0
	bl	clean_dcache_range

	adrp	x0, __PER_CPU_START__
	add	x0, x0, :lo12:__PER_CPU_START__
	adrp	x1, __PER_CPU_END__
	add	x1, x1, :lo12:__PER_CPU_END__
	sub	x1, x1, x0
	bl	clean_dcache_range

#if (PLATFORM_NODE_COUNT > 1)
	/*
	 * 清理平台定义的每CPU段的dcache。
	 * 必须注意保留和恢复被破坏的寄存器。
	 * 目前尚未定义围绕每CPU节点的标准容器。
	 */

	bl	plat_per_cpu_dcache_clean
#endif /* (PLATFORM_NODE_COUNT > 1) */
	b	el3_exit
endfunc bl31_entrypoint

	/* --------------------------------------------------------------------
	 * 此CPU已被物理唤醒。它要么是从挂起状态恢复，要么是刚刚开机。
	 * 在这两种情况下，调用 BL31 热启动入口点。
	 * --------------------------------------------------------------------
	 */
func bl31_warm_entrypoint
#if ENABLE_RUNTIME_INSTRUMENTATION

	/*
	 * 这个时间戳更新发生在缓存关闭的情况下。
	 * 下一次时间戳收集需要在更新时间戳之前进行缓存维护。
	 */
	pmf_calc_timestamp_addr rt_instr_svc, RT_INSTR_EXIT_HW_LOW_PWR
	mrs	x1, cntpct_el0
	str	x1, [x0]
#endif

	/*
	 * 在热启动路径上，必须跳过 'el3_entrypoint_common' 执行的大部分EL3初始化：
	 *
	 *  - 只有当平台通过编程复位地址绕过 BL1/BL31 入口点时，
	 *    才需要初始化 SCTLR_EL3。在其他情况下，我们假设入口点代码已经处理了这一点。
	 *
	 *  - 不需要确定启动类型，我们知道这是一个热启动。
	 *
	 *  - 不要尝试区分主CPU和从CPU，这个概念仅存在于冷启动中。
	 *
	 *  - 不需要初始化内存或C运行时环境，这些已经在冷启动路径上完成了一次性初始化。
	 */
	el3_entrypoint_common					\
		_init_sctlr=PROGRAMMABLE_RESET_ADDRESS		\
		_warm_boot_mailbox=0				\
		_secondary_cold_boot=0				\
		_init_memory=0					\
		_init_c_runtime=0				\
		_exception_vectors=runtime_exceptions		\
		_pie_fixup_size=0

	bl	bl31_warmboot

#if ENABLE_RUNTIME_INSTRUMENTATION
	pmf_calc_timestamp_addr rt_instr_svc, RT_INSTR_EXIT_PSCI
	mov	x19, x0

	/*
	 * 在更新时间戳之前使缓存失效，以确保在禁用缓存的情况下，
	 * 对同一缓存行的先前时间戳更新能被同核心正确看到。
	 * 如果没有缓存失效，核心可能会写入陈旧的缓存行。
	 */
	mov	x1, #PMF_TS_SIZE
	mov	x20, x30
	bl	inv_dcache_range
	mov	x30, x20

	mrs	x0, cntpct_el0
	str	x0, [x19]
#endif
	b	el3_exit
endfunc bl31_warm_entrypoint