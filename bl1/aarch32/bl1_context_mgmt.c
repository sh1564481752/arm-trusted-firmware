/*
 * 版权所有 (c) 2016-2020, ARM Limited 和贡献者保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <plat/common/platform.h>

#include <arch_helpers.h>
#include <common/debug.h>
#include <context.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <smccc_helpers.h>

#include "../bl1_private.h"

/*
 * 以下数组将用于上下文管理。
 * 共有2个实例，分别用于安全和非安全上下文。
 */
static cpu_context_t bl1_cpu_context[2];
static smc_ctx_t bl1_smc_context[2];

/* 存储下一个CPU上下文指针 */
static void *bl1_next_cpu_context_ptr;

/* 存储下一个SMC上下文指针 */
static void *bl1_next_smc_context_ptr;

/* 以下函数用于SMC上下文处理 */
/**
 * 获取指定安全状态的SMC上下文
 * @param security_state 安全状态(SECURE/NON_SECURE)
 * @return 指向对应SMC上下文的指针
 */
void *smc_get_ctx(unsigned int security_state)
{
	assert(sec_state_is_valid(security_state));
	return &bl1_smc_context[security_state];
}

/**
 * 设置下一个要使用的SMC上下文
 * @param security_state 安全状态(SECURE/NON_SECURE)
 */
void smc_set_next_ctx(unsigned int security_state)
{
	assert(sec_state_is_valid(security_state));
	bl1_next_smc_context_ptr = &bl1_smc_context[security_state];
}

/**
 * 获取下一个要使用的SMC上下文
 * @return 指向下一个SMC上下文的指针
 */
void *smc_get_next_ctx(void)
{
	return bl1_next_smc_context_ptr;
}

/* 以下函数用于CPU上下文处理 */
/**
 * 获取指定安全状态的CPU上下文
 * @param security_state 安全状态(SECURE/NON_SECURE)
 * @return 指向对应CPU上下文的指针
 */
void *cm_get_context(size_t security_state)
{
	assert(sec_state_is_valid(security_state));
	return &bl1_cpu_context[security_state];
}

/**
 * 设置下一个要使用的CPU上下文
 * @param context 要设置的上下文指针
 */
void cm_set_next_context(void *context)
{
	assert(context != NULL);
	bl1_next_cpu_context_ptr = context;
}

/**
 * 获取下一个要使用的CPU上下文
 * @return 指向下一个CPU上下文的指针
 */
void *cm_get_next_context(void)
{
	return bl1_next_cpu_context_ptr;
}

/*******************************************************************************
 * 以下函数将通用寄存器r0-r4、lr和spsr从CPU上下文复制到SMC上下文结构体中
 * 这是为了在安全监控调用(SMC)期间保存处理器状态
 ******************************************************************************/
static void copy_cpu_ctx_to_smc_ctx(const regs_t *cpu_reg_ctx,
				    smc_ctx_t *next_smc_ctx)
{
	next_smc_ctx->r0 = read_ctx_reg(cpu_reg_ctx, CTX_GPREG_R0);
	next_smc_ctx->r1 = read_ctx_reg(cpu_reg_ctx, CTX_GPREG_R1);
	next_smc_ctx->r2 = read_ctx_reg(cpu_reg_ctx, CTX_GPREG_R2);
	next_smc_ctx->r3 = read_ctx_reg(cpu_reg_ctx, CTX_GPREG_R3);
	next_smc_ctx->lr_mon = read_ctx_reg(cpu_reg_ctx, CTX_LR);
	next_smc_ctx->spsr_mon = read_ctx_reg(cpu_reg_ctx, CTX_SPSR);
	next_smc_ctx->scr = read_ctx_reg(cpu_reg_ctx, CTX_SCR);
}

/*******************************************************************************
 * 以下函数刷新SMC和CPU上下文指针及其数据到内存
 * 确保在禁用缓存后仍能正确访问这些数据
 ******************************************************************************/
static void flush_smc_and_cpu_ctx(void)
{
	flush_dcache_range((uintptr_t)&bl1_next_smc_context_ptr,
			   sizeof(bl1_next_smc_context_ptr));
	flush_dcache_range((uintptr_t)bl1_next_smc_context_ptr,
			   sizeof(smc_ctx_t));

	flush_dcache_range((uintptr_t)&bl1_next_cpu_context_ptr,
			   sizeof(bl1_next_cpu_context_ptr));
	flush_dcache_range((uintptr_t)bl1_next_cpu_context_ptr,
			   sizeof(cpu_context_t));
}

/*******************************************************************************
 * 此函数为安全/正常世界镜像准备上下文
 * 正常世界镜像将转换到HYP模式(如果支持)，否则转换到SVC模式
 * 这是BL1阶段的重要函数，负责设置下一阶段启动所需的处理器状态
 ******************************************************************************/
void bl1_prepare_next_image(unsigned int image_id)
{
	unsigned int security_state, mode = MODE32_svc;
	image_desc_t *desc;
	entry_point_info_t *next_bl_ep;

	/* 获取镜像描述符 */
	desc = bl1_plat_get_image_desc(image_id);
	assert(desc != NULL);

	/* 获取入口点信息 */
	next_bl_ep = &desc->ep_info;

	/* 获取镜像的安全状态 */
	security_state = GET_SECURITY_STATE(next_bl_ep->h.attr);

	/* 为下一个BL镜像准备SPSR(程序状态寄存器) */
	if ((security_state != SECURE) &&
	    (GET_VIRT_EXT(read_id_pfr1()) != 0U)) {
		mode = MODE32_hyp;
	}

	next_bl_ep->spsr = SPSR_MODE32(mode, SPSR_T_ARM, SPSR_E_LITTLE,
				       DISABLE_ALL_EXCEPTIONS);

	/* 允许平台进行修改 */
	bl1_plat_set_ep_info(image_id, next_bl_ep);

	/* 为下一个BL镜像准备CPU上下文 */
	cm_init_my_context(next_bl_ep);
	cm_prepare_el3_exit(security_state);
	cm_set_next_context(cm_get_context(security_state));

	/* 为下一个BL镜像准备SMC上下文 */
	smc_set_next_ctx(security_state);
	copy_cpu_ctx_to_smc_ctx(get_regs_ctx(cm_get_next_context()),
				smc_get_next_ctx());

	/*
	 * 如果下一个镜像是非安全的，则需要编程银行化的非安全SCTLR。
	 * 当下一个镜像是安全的时候不需要这样做，因为在AArch32中，
	 * 我们期望安全世界具有相同的SCTLR设置。
	 */
	if (security_state == NON_SECURE) {
		cpu_context_t *ctx = cm_get_context(security_state);
		u_register_t ns_sctlr;

		/* 临时设置NS位以访问非安全SCTLR */
		write_scr(read_scr() | SCR_NS_BIT);
		isb();

		ns_sctlr = read_ctx_reg(get_regs_ctx(ctx), CTX_NS_SCTLR);
		write_sctlr(ns_sctlr);
		isb();

		write_scr(read_scr() & ~SCR_NS_BIT);
		isb();
	}

	/*
	 * 刷新SMC和CPU上下文以及(下一个)指针，
	 * 以便在禁用缓存后能够访问它们。
	 */
	flush_smc_and_cpu_ctx();

	/* 标记镜像处于执行状态 */
	desc->state = IMAGE_STATE_EXECUTED;

	print_entry_point_info(next_bl_ep);
}