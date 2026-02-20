/*
 * Copyright (c) 2017-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <platform_def.h>

#include <arch.h>
#include <asm_macros.S>
#include <common/bl_common.h>
#include <el3_common_macros.S>

	.globl	bl2_entrypoint

#if BL2_IN_XIP_MEM || ENABLE_RME
#define FIXUP_SIZE	0
#else
#define FIXUP_SIZE	((BL2_LIMIT) - (BL2_BASE))
#endif

/*
 * 函数名称: bl2_entrypoint
 * 功能描述: BL2阶段的入口点函数，负责初始化BL2运行环境并跳转到主函数执行。
 * 参数说明:
 *   x0-x3: 来自上一阶段引导加载程序的参数，保存在寄存器x20-x23中以供后续使用。
 * 返回值: 无直接返回值，正常流程下应跳转至bl2_main函数执行，异常情况下调用plat_panic_handler处理。
 */
func bl2_entrypoint
	/* 保存来自上一阶段引导加载程序的参数x0-x3 */
	mov	x20, x0
	mov	x21, x1
	mov	x22, x2
	mov	x23, x3

	/*
	 * 调用通用EL3入口点初始化函数，完成以下操作：
	 * 1. 初始化系统控制寄存器(SCTLR)；
	 * 2. 根据配置决定是否启用热启动邮箱机制；
	 * 3. 根据配置决定是否支持多核冷启动；
	 * 4. 初始化内存相关设置；
	 * 5. 初始化C运行时环境；
	 * 6. 设置异常向量表为bl2_el3_exceptions；
	 * 7. 根据FIXUP_SIZE进行位置无关代码修正。
	 */
	el3_entrypoint_common							\
		_init_sctlr=RESET_TO_BL2					\
		_warm_boot_mailbox=!PROGRAMMABLE_RESET_ADDRESS && RESET_TO_BL2	\
		_secondary_cold_boot=!COLD_BOOT_SINGLE_CPU && RESET_TO_BL2	\
		_init_memory=RESET_TO_BL2					\
		_init_c_runtime=1						\
		_exception_vectors=bl2_el3_exceptions				\
		_pie_fixup_size=FIXUP_SIZE

	/* 恢复之前保存的引导加载程序参数 */
	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23

	/* 跳转到BL2主函数执行 */
	bl	bl2_main

	/*
	 * 正常流程不应到达此处。如果执行到这里，说明发生了严重错误，
	 * 调用平台特定的恐慌处理函数进行错误处理。
	 */
	no_ret	plat_panic_handler
endfunc bl2_entrypoint