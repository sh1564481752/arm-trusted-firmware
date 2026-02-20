/*
 * Copyright (c) 2013-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <asm_macros.S>
#include <common/bl_common.h>


	.globl	bl2_entrypoint



func bl2_entrypoint
	/*---------------------------------------------
	 * 保存来自BL1的参数x0-x3以供将来使用
	 * 这些参数包含了BL1传递给BL2的重要信息
	 * ---------------------------------------------
	 */
	mov	x20, x0
	mov	x21, x1
	mov	x22, x2
	mov	x23, x3

	/* ---------------------------------------------
	 * 设置异常向量表到一个合理的地址
	 * early_exceptions是在其他地方定义的异常处理函数
	 * ---------------------------------------------
	 */
	adr	x0, early_exceptions
	msr	vbar_el1, x0
	isb

	/* ---------------------------------------------
	 * 使能SError中断
	 * 现在异常向量表已经设置完成，可以安全地启用中断
	 * ---------------------------------------------
	 */
	msr	daifclr, #DAIF_ABT_BIT

	/* ---------------------------------------------
	 * 使能指令缓存、栈指针对齐检查和数据访问对齐检查
	 * 同时禁用推测加载以提高安全性
	 * ---------------------------------------------
	 */
	mov	x1, #(SCTLR_I_BIT | SCTLR_A_BIT | SCTLR_SA_BIT)
	mrs	x0, sctlr_el1
	orr	x0, x0, x1
#if ENABLE_BTI
	/* 启用PAC分支类型兼容性 */
	bic     x0, x0, #(SCTLR_BT0_BIT | SCTLR_BT1_BIT)
#endif
	bic	x0, x0, #SCTLR_DSSBS_BIT
	msr	sctlr_el1, x0
	isb

	/* ---------------------------------------------
	 * 使无效BL2镜像使用的读写内存
	 * 包括数据段和NOBITS段
	 * 这样做是为了防止系统缓存中脏缓存行可能造成的内存损坏
	 * 这些脏缓存行可能是早期引导加载程序阶段使用的结果
	 * ---------------------------------------------
	 */
	adr	x0, __RW_START__
	adr	x1, __RW_END__
	sub	x1, x1, x0
	bl	inv_dcache_range

	/* ---------------------------------------------
	 * 清零NOBITS段，共有两个：
	 *   - .bss段；
	 *   - 一致内存段。
	 * ---------------------------------------------
	 */
	adrp	x0, __BSS_START__
	add	x0, x0, :lo12:__BSS_START__
	adrp	x1, __BSS_END__
	add	x1, x1, :lo12:__BSS_END__
	sub	x1, x1, x0
	bl	zeromem

#if USE_COHERENT_MEM
	adrp	x0, __COHERENT_RAM_START__
	add	x0, x0, :lo12:__COHERENT_RAM_START__
	adrp	x1, __COHERENT_RAM_END_UNALIGNED__
	add	x1, x1, :lo12:__COHERENT_RAM_END_UNALIGNED__
	sub	x1, x1, x0
	bl	zeromem
#endif

	/* --------------------------------------------
	 * 分配一个栈，当MMU启用时其内存将被标记为Normal-IS-WBWA
	 * 由于此时只有主CPU在运行，因此启用MMU后读取陈旧栈内存没有风险
	 * --------------------------------------------
	 */
	bl	plat_set_my_stack

	/* ---------------------------------------------
	 * 在调用任何C代码之前初始化栈保护器金丝雀值
	 * 用于检测栈溢出攻击
	 * ---------------------------------------------
	 */
#if STACK_PROTECTOR_ENABLED
	bl	update_stack_protector_canary
#endif

	/* ---------------------------------------------
	 * 执行BL2设置
	 * 恢复之前保存的参数
	 * ---------------------------------------------*/
	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23

	/* ---------------------------------------------
	 * 跳转到主函数
	 * 这是BL2的主要逻辑入口点
	 * ---------------------------------------------*/
	bl	bl2_main

	/* ---------------------------------------------
	 * 不应该到达这一点
	 * 如果执行到这里说明出现了严重错误
	 * ---------------------------------------------*/
	no_ret	plat_panic_handler

endfunc bl2_entrypoint