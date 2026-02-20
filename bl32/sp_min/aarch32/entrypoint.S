/*
 * 版权所有 (c) 2016-2025, Arm Limited and Contributors. 保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <asm_macros.S>
#include <common/bl_common.h>
#include <common/runtime_svc.h>
#include <context.h>
#include <el3_common_macros.S>
#include <lib/el3_runtime/cpu_data.h>
#include <lib/pmf/aarch32/pmf_asm_macros.S>
#include <lib/runtime_instr.h>
#include <lib/xlat_tables/xlat_tables_defs.h>
#include <smccc_helpers.h>
#include <smccc_macros.S>

    .globl	sp_min_vector_table
    .globl	sp_min_entrypoint
    .globl	sp_min_warm_entrypoint
    .globl	sp_min_handle_smc
    .globl	sp_min_handle_fiq

#define FIXUP_SIZE	((BL32_LIMIT) - (BL32_BASE))

    .macro route_fiq_to_sp_min reg
        /* -----------------------------------------------------
         * 将 FIQ 路由到 Monitor（SP_MIN）。FIQ 是被 Monitor 捕获的安全中断，
         * 非安全端不能屏蔽 FIQ。
         * ----------------------------------------------------- */
        ldcopr	\reg, SCR
        orr	\reg, \reg, #SCR_FIQ_BIT
        bic	\reg, \reg, #SCR_FW_BIT
        stcopr	\reg, SCR
    .endm

    .macro clrex_on_monitor_entry
#if (ARM_ARCH_MAJOR == 7)
    /*
     * ARMv7 架构在进入 Monitor 模式时需要清除独占访问状态。
     */
    clrex
#endif
    .endm

/* 向量表基址：为各类异常/中断指定入口点 */
vector_base sp_min_vector_table
    b	sp_min_entrypoint
    b	plat_panic_handler		/* 未定义：平台 panic 处理 */
    b	sp_min_handle_smc		/* SMC（系统调用）处理 */
    b	report_prefetch_abort	/* 预取异常 */
    b	report_data_abort		/* 数据异常 */
    b	plat_panic_handler		/* 保留 */
    b	plat_panic_handler		/* IRQ（普通中断） */
    b	sp_min_handle_fiq		/* FIQ（快速中断） */


/*
 * sp_min_entrypoint：SP_MIN 的冷启动 / 复位入口
 * - 保存前一阶段传入的 r0-r3 以供后续使用
 * - 根据配置执行 el3_entrypoint_common 完成 EL3 层面的初始化
 * - 调用 sp_min_setup 和 sp_min_main 执行平台和运行时初始化
 * - 清理数据缓存，确保主核初始化的数据对次核可见
 * - 恢复 SMC 上下文并通过 monitor_exit 返回
 */
func sp_min_entrypoint
    /* ---------------------------------------------------------------
     * 保存前级引导器传入的 r0 - r3，供之后传递给平台层使用。
     * --------------------------------------------------------------- */
    mov	r9, r0
    mov	r10, r1
    mov	r11, r2
    mov	r12, r3

/* ...existing code... */

    /* 将之前保存的参数转发给平台层 */
    mov	r0, r9
    mov	r1, r10
    mov	r2, r11
    mov	r3, r12
    bl	sp_min_setup

    /* 跳转到 C 层主入口 */
    bl	sp_min_main

/* ...existing code... */

    /* 从 PSCI/SMC 获取下一个上下文并返回到 monitor */
    bl	smc_get_next_ctx

    /* r0 指向 smc_ctx_t（SMC 上下文） */
    b	sp_min_exit
endfunc sp_min_entrypoint


/*
 * sp_min_handle_smc：处理进入 Monitor 的 SMC 调用
 * - sp 指向 smc_ctx_t；在入口保存 lr，并保存必要寄存器
 * - 根据需要记录运行时时间戳（若启用运行时计量）
 * - 切换到 Secure 模式（清除 SCR 的 NS 位），然后调用 handle_runtime_svc
 * - 支持检测 SMC64/SMC32，格式不正确时返回错误给调用者
 */
func sp_min_handle_smc
    /* 在 SMC 入口时，sp 指向 smc_ctx_t，先保存 lr 到上下文 */
    str	lr, [sp, #SMC_CTX_LR_MON]

/* ...existing code... */

    /* 保存 smc_ctx_t 句柄并恢复 C 运行时栈指针 */
    mov	r2, sp				/* handle */
    ldr	sp, [r2, #SMC_CTX_SP_MON]

/* ...existing code... */

    /* 切换到 Secure 模式：清除 SCR 中的 NS 位并执行 ISB */
    ldr	r0, [r2, #SMC_CTX_SCR]
    and	r3, r0, #SCR_NS_BIT		/* flags */
    bic	r0, #SCR_NS_BIT
    stcopr	r0, SCR
    isb

    /* 获取 smc_fid，并判断是否为 SMC64 格式 */
    ldr	r0, [r2, #SMC_CTX_GPREG_R0]	/* smc_fid */
    tst	r0, #(FUNCID_CC_MASK << FUNCID_CC_SHIFT)
    beq	1f
    /* 非 SMC32 请求：返回未知 SMC 错误给调用者 */
    mov	r0, #SMC_UNK
    str	r0, [r2, #SMC_CTX_GPREG_R0]
    mov	r0, r2
    b	sp_min_exit
1:
    /* 是 SMC32：调用 C 层运行时服务处理函数 */
    mov	r1, #0				/* cookie */
    bl	handle_runtime_svc

    /* handle_runtime_svc 返回时 r0 指向 smc_ctx_t，随后返回 */
    b	sp_min_exit
endfunc sp_min_handle_smc

/*
 * sp_min_handle_fiq：处理 Secure FIQ（快速中断）
 * - 若未启用 Secure FIQ，直接进入平台 panic
 * - 否则保存上下文、切换到 Secure 模式并调用 sp_min_fiq 进行高层处理
 */
func sp_min_handle_fiq
#if !SP_MIN_WITH_SECURE_FIQ
    b plat_panic_handler
#else
    /* lr 相对于首选返回地址有 +4 偏移，修正后保存 */
    sub	lr, lr, #4
    /* 在 SMC/中断入口时，sp 指向 smc_ctx_t，保存 lr */
    str	lr, [sp, #SMC_CTX_LR_MON]

/* ...existing code... */

    /* 切换到 Secure 模式并调用高层 FIQ 处理函数 */
    push	{r2, r3}
    bl	sp_min_fiq
    pop	{r0, r3}

    b	sp_min_exit
#endif
endfunc sp_min_handle_fiq

/*
 * sp_min_warm_entrypoint：SP_MIN 的热重启入口
 * - 热重启路径跳过冷启动时需要的多数初始化
 * - 根据平台配置决定是否在启用 MMU 时同时启用数据缓存
 * - 恢复 SMC 上下文并返回
 */
func sp_min_warm_entrypoint
/* ...existing code... */

    /* 启用 MMU（并根据平台决定是否启用数据缓存） */
#if HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY
    mov	r0, #0
#else
    mov	r0, #DISABLE_DCACHE
#endif
    bl	bl32_plat_enable_mmu

/* ...existing code... */

    /* 完成 warm boot 平台初始化并恢复 smc_ctx，随后返回 */
    bl	sp_min_warm_boot
    bl	smc_get_next_ctx
/* ...existing code... */
    b	sp_min_exit
endfunc sp_min_warm_entrypoint

/*
 * sp_min_exit：从 smc_ctx 恢复寄存器并返回到调用者（monitor_exit）
 * - 入口参数：r0 必须指向要恢复的 smc_ctx_t
 */
func sp_min_exit
    monitor_exit
endfunc sp_min_exit
