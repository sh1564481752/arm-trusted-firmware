/*
 * 版权所有 (c) 2018, ARM Limited and Contributors。保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <asm_macros.S>

    .globl	wa_cve_2017_5715_icache_inv_vbar

vector_base wa_cve_2017_5715_icache_inv_vbar
    /* 我们在 SP 的最低 3 位编码异常入口 */
    add	sp, sp, #1	/* 复位: 0b111 */
    add	sp, sp, #1	/* 未定义: 0b110 */
    add	sp, sp, #1	/* 系统调用: 0b101 */
    add	sp, sp, #1	/* 预取异常: 0b100 */
    add	sp, sp, #1	/* 数据异常: 0b011 */
    add	sp, sp, #1	/* 保留: 0b010 */
    add	sp, sp, #1	/* IRQ: 0b001 */
    nop			/* FIQ: 0b000 */

    /*
     * 使指令缓存失效，假定这也会使分支预测器失效。
     * 具体行为可能依赖于其他 CPU 特定设置（例如 ACTLR）。
     */
    stcopr	r0, ICIALLU
    isb

    /*
     * 由于不能使用临时寄存器且不能修改 SP，我们通过展开的二分查找来解码异常入口。
     *
     * 注意：如果此代码被其他安全负载复用，下方的异常入口向量必须改为对应安全负载的向量。
     */

    tst	sp, #4
    bne	1f

    tst	sp, #2
    bne	3f

    /* 期望编码：0x1 和 0x0 */
    tst	sp, #1
    /* 通过清除最低 3 位恢复 SP 的原始值 */
    bic	sp, sp, #0x7
    bne	plat_panic_handler	/* IRQ（普通中断） */
    b	sp_min_handle_fiq	/* FIQ（快速中断） */

1:
    /* 期望编码：0x4 和 0x5 */
    tst	sp, #2
    bne	2f

    tst	sp, #1
    bic	sp, sp, #0x7
    bne	sp_min_handle_smc	/* 系统调用 */
    b	plat_panic_handler	/* 预取异常 */

2:
    /* 期望编码：0x7 和 0x6 */
    tst	sp, #1
    bic	sp, sp, #0x7
    bne	sp_min_entrypoint	/* 复位 */
    b	plat_panic_handler	/* 未定义 */

3:
    /* 期望编码：0x2 和 0x3 */
    tst	sp, #1
    bic	sp, sp, #0x7
    bne	plat_panic_handler	/* 数据异常 */
    b	plat_panic_handler	/* 保留 */