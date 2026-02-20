/*
 * Copyright (c) 2013-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <common/bl_common.h>
#include <el3_common_macros.S>

	.globl	bl1_entrypoint
	.globl	bl1_run_bl2_in_root


	/* -----------------------------------------------------
	 * bl1_entrypoint() 是 CPU 从冷启动或热启动复位后进入可信固件代码的入口点。
	 * 此函数负责初始化系统并跳转到下一个启动阶段。
	 * -----------------------------------------------------
	 */

func bl1_entrypoint
	/* ---------------------------------------------------------------------
	 * 如果复位地址是可编程的，则 bl1_entrypoint() 仅在冷启动路径上执行。
	 * 因此可以跳过热启动邮箱机制。
	 * ---------------------------------------------------------------------
	 */
	el3_entrypoint_common					\
		_init_sctlr=1					\
		_warm_boot_mailbox=!PROGRAMMABLE_RESET_ADDRESS	\
		_secondary_cold_boot=!COLD_BOOT_SINGLE_CPU	\
		_init_memory=1					\
		_init_c_runtime=1				\
		_exception_vectors=bl1_exceptions		\
		_pie_fixup_size=0

	/* --------------------------------------------------------------------
	 * 初始化平台并跳转到当前复位类型的 C 入口点。
	 * --------------------------------------------------------------------
	 */
	bl	bl1_main

	/* --------------------------------------------------
	 * 执行到下一启动镜像的转换。
	 * --------------------------------------------------
	 */
#if ENABLE_RME
	b	bl1_run_bl2_in_root
#else
	b	el3_exit
#endif
endfunc bl1_entrypoint

	/* -----------------------------------------------------
	 * void bl1_run_bl2_in_root();
	 * 当启用 RME（Realm Management Extension）时，
	 * 此函数在根/EL3 模式下运行 BL2。
	 * -----------------------------------------------------
	 */

func bl1_run_bl2_in_root
	/* 读取 bl2_ep_info 结构体的地址 */
	adrp	x20, bl2_ep_info
	add	x20, x20, :lo12:bl2_ep_info
	ldr	x20, [x20]

	/* ---------------------------------------------
	 * 需要禁用 MMU，因为 BL2 在 EL3 中执行。
	 * 它将根据自身需求重新初始化地址空间。
	 * ---------------------------------------------
	 */
	bl	disable_mmu_icache_el3
	tlbi	alle3

	/* 加载入口点信息中的程序计数器和状态寄存器值 */
	ldp	x0, x1, [x20, #ENTRY_POINT_INFO_PC_OFFSET]
	msr	elr_el3, x0
	msr	spsr_el3, x1

	/* 加载传递给 BL2 的参数 */
	ldp	x6, x7, [x20, #(ENTRY_POINT_INFO_ARGS_OFFSET + 0x30)]
	ldp	x4, x5, [x20, #(ENTRY_POINT_INFO_ARGS_OFFSET + 0x20)]
	ldp	x2, x3, [x20, #(ENTRY_POINT_INFO_ARGS_OFFSET + 0x10)]
	ldp	x0, x1, [x20, #(ENTRY_POINT_INFO_ARGS_OFFSET + 0x0)]
	exception_return
endfunc bl1_run_bl2_in_root