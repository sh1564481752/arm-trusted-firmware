/*
 * 版权所有 (c) 2016-2025, Arm Limited 及其贡献者。保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <plat/common/platform.h>
#include <platform_def.h>

#include <arch.h>
#include <arch_helpers.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <context.h>
#include <drivers/console.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/pmf/pmf.h>
#include <lib/psci/psci.h>
#include <lib/runtime_instr.h>
#include <lib/utils.h>
#include <platform_sp_min.h>
#include <services/std_svc.h>
#include <smccc_helpers.h>

#include "sp_min_private.h"

#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE_SMC(rt_instr_svc, PMF_RT_INSTR_SVC_ID, RT_INSTR_TOTAL_IDS,
			 PMF_STORE_ENABLE)
#endif

/* 指向每个核心CPU上下文的指针 */
static void *sp_min_cpu_ctx_ptr[PLATFORM_CORE_COUNT];

/* SP_MIN仅存储非安全SMC上下文 */
static smc_ctx_t sp_min_smc_context[PLATFORM_CORE_COUNT];

/******************************************************************************
 * 获取指定安全状态下的SMC上下文指针。
 *
 * 参数:
 *   security_state - 安全状态，必须为NON_SECURE。
 *
 * 返回值:
 *   指向当前核心的非安全SMC上下文的指针。
 ******************************************************************************/
void *smc_get_ctx(unsigned int security_state)
{
	assert(security_state == NON_SECURE);
	return &sp_min_smc_context[plat_my_core_pos()];
}

/******************************************************************************
 * 设置下一个SMC上下文的安全状态。
 *
 * 参数:
 *   security_state - 安全状态，必须为NON_SECURE。
 ******************************************************************************/
void smc_set_next_ctx(unsigned int security_state)
{
	assert(security_state == NON_SECURE);
	/* SP_MIN仅存储非安全SMC上下文。这里无需执行任何操作 */
}

/******************************************************************************
 * 获取下一个SMC上下文的指针。
 *
 * 返回值:
 *   指向当前核心的非安全SMC上下文的指针。
 ******************************************************************************/
void *smc_get_next_ctx(void)
{
	return &sp_min_smc_context[plat_my_core_pos()];
}

/*******************************************************************************
 * 获取指定安全状态下调用CPU的最近一次设置的CPU上下文结构体指针。
 *
 * 参数:
 *   security_state - 安全状态，必须为NON_SECURE。
 *
 * 返回值:
 *   指向CPU上下文结构体的指针，如果未设置则返回NULL。
 ******************************************************************************/
void *cm_get_context(size_t security_state)
{
	assert(security_state == NON_SECURE);
	return sp_min_cpu_ctx_ptr[plat_my_core_pos()];
}

/*******************************************************************************
 * 为调用CPU设置指定安全状态下的当前CPU上下文结构体指针。
 *
 * 参数:
 *   context - 指向CPU上下文结构体的指针。
 *   security_state - 安全状态，必须为NON_SECURE。
 ******************************************************************************/
void cm_set_context(void *context, uint32_t security_state)
{
	assert(security_state == NON_SECURE);
	sp_min_cpu_ctx_ptr[plat_my_core_pos()] = context;
}

/*******************************************************************************
 * 获取由CPU索引标识的CPU在指定安全状态下的最近一次设置的CPU上下文结构体指针。
 *
 * 参数:
 *   cpu_idx - CPU索引。
 *   security_state - 安全状态，必须为NON_SECURE。
 *
 * 返回值:
 *   指向CPU上下文结构体的指针，如果未设置则返回NULL。
 ******************************************************************************/
void *cm_get_context_by_index(unsigned int cpu_idx, size_t security_state)
{
	assert(security_state == NON_SECURE);
	return sp_min_cpu_ctx_ptr[cpu_idx];
}

/*******************************************************************************
 * 为由CPU索引标识的CPU设置指定安全状态下的当前CPU上下文结构体指针。
 *
 * 参数:
 *   cpu_idx - CPU索引。
 *   context - 指向CPU上下文结构体的指针。
 *   security_state - 安全状态，必须为NON_SECURE。
 ******************************************************************************/
void cm_set_context_by_index(unsigned int cpu_idx, void *context,
			     unsigned int security_state)
{
	assert(security_state == NON_SECURE);
	sp_min_cpu_ctx_ptr[cpu_idx] = context;
}

/******************************************************************************
 * 将CPU寄存器上下文复制到SMC上下文中。
 *
 * 参数:
 *   cpu_reg_ctx - 指向CPU寄存器上下文的指针。
 *   next_smc_ctx - 指向目标SMC上下文的指针。
 ******************************************************************************/
static void copy_cpu_ctx_to_smc_stx(const regs_t *cpu_reg_ctx,
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
 * 调用PSCI库接口初始化非安全CPU上下文，并将相关CPU上下文寄存器值复制到SMC上下文中。
 ******************************************************************************/
static void sp_min_prepare_next_image_entry(void)
{
	entry_point_info_t *next_image_info;
	regs_t *gpregs = get_regs_ctx(cm_get_context(NON_SECURE));
	u_register_t ns_sctlr;

	/* 编程系统寄存器以继续到非安全状态 */
	next_image_info = sp_min_plat_get_bl33_ep_info();
	assert(next_image_info);
	assert(NON_SECURE == GET_SECURITY_STATE(next_image_info->h.attr));

	INFO("SP_MIN: 准备退出到正常世界\n");
	print_entry_point_info(next_image_info);

	psci_prepare_next_non_secure_ctx(next_image_info);
	smc_set_next_ctx(NON_SECURE);

	/* 将r0、lr和spsr从CPU上下文复制到SMC上下文 */
	copy_cpu_ctx_to_smc_stx(gpregs, smc_get_next_ctx());

	/* 临时设置NS位以访问NS SCTLR */
	write_scr(read_scr() | SCR_NS_BIT);
	isb();
	ns_sctlr = read_ctx_reg(gpregs, CTX_NS_SCTLR);
	write_sctlr(ns_sctlr);
	isb();

	write_scr(read_scr() & ~SCR_NS_BIT);
	isb();
}

/******************************************************************************
 * 实现ARM标准服务函数以获取特定服务的参数。
 *
 * 参数:
 *   svc_mask - 服务掩码，必须为PSCI_FID_MASK。
 *
 * 返回值:
 *   指向PSCI库参数的指针。
 ******************************************************************************/
uintptr_t get_arm_std_svc_args(unsigned int svc_mask)
{
	/* 为PSCI库设置参数 */
	DEFINE_STATIC_PSCI_LIB_ARGS_V1(psci_args, sp_min_warm_entrypoint);

	/* PSCI是唯一实现的ARM标准服务 */
	assert(svc_mask == PSCI_FID_MASK);

	return (uintptr_t)&psci_args;
}

/******************************************************************************
 * SP_MIN初始化函数。调用平台初始化函数。
 *
 * 参数:
 *   arg0 - 初始化参数0。
 *   arg1 - 初始化参数1。
 *   arg2 - 初始化参数2。
 *   arg3 - 初始化参数3。
 ******************************************************************************/
void sp_min_setup(u_register_t arg0, u_register_t arg1, u_register_t arg2,
		  u_register_t arg3)
{
	/* 如果启用了EARLY_CONSOLE标志，则启用早期控制台 */
	plat_setup_early_console();

	/* 执行平台特定的早期设置 */
	sp_min_early_platform_setup2(arg0, arg1, arg2, arg3);
	sp_min_plat_arch_setup();
}

/******************************************************************************
 * SP_MIN主函数。执行平台和PSCI库设置，并初始化运行时服务框架。
 ******************************************************************************/
void sp_min_main(void)
{
	NOTICE("SP_MIN: %s\n", build_version_string);
	NOTICE("SP_MIN: %s\n", build_message);

	/* 执行SP_MIN平台设置 */
	sp_min_platform_setup();

	/* 初始化运行时服务，例如PSCI */
	INFO("SP_MIN: 初始化运行时服务\n");
	runtime_svc_init();

	/*
	 * 我们已准备好进入下一个EL。准备在下一次ERET之后进入对应所需安全状态的镜像。
	 */
	sp_min_prepare_next_image_entry();

	/*
	 * 在从SP_MIN退出冷启动之前执行任何平台特定的运行时设置。
	 */
	sp_min_plat_runtime_setup();

	console_flush();
	console_switch_state(CONSOLE_FLAG_RUNTIME);
}

/******************************************************************************
 * 在热启动时调用此函数。调用PSCI库热启动入口点，处理架构和平台设置/恢复。
 ******************************************************************************/
void sp_min_warm_boot(void)
{
	smc_ctx_t *next_smc_ctx;
	regs_t *gpregs = get_regs_ctx(cm_get_context(NON_SECURE));
	u_register_t ns_sctlr;

	psci_warmboot_entrypoint(plat_my_core_pos());

	smc_set_next_ctx(NON_SECURE);

	next_smc_ctx = smc_get_next_ctx();
	zeromem(next_smc_ctx, sizeof(smc_ctx_t));

	copy_cpu_ctx_to_smc_stx(gpregs, next_smc_ctx);

	/* 临时设置NS位以访问NS SCTLR */
	write_scr(read_scr() | SCR_NS_BIT);
	isb();
	ns_sctlr = read_ctx_reg(gpregs, CTX_NS_SCTLR);
	write_sctlr(ns_sctlr);
	isb();

	write_scr(read_scr() & ~SCR_NS_BIT);
	isb();
}

#if SP_MIN_WITH_SECURE_FIQ
/******************************************************************************
 * 在安全中断发生时调用此函数。仅当核心在非安全状态下执行时才能处理安全中断。
 ******************************************************************************/
void sp_min_fiq(void)
{
	uint32_t id;

	id = plat_ic_acknowledge_interrupt();
	sp_min_plat_fiq_handler(id);
	plat_ic_end_of_interrupt(id);
}
#endif /* SP_MIN_WITH_SECURE_FIQ */