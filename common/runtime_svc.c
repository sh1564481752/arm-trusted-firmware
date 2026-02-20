/*
 * Copyright (c) 2013-2026, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <plat/common/platform.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <bl31/ea_handle.h>
#include <bl31/interrupt_mgmt.h>
#include <bl31/sync_handle.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <context.h>
#include <lib/cpus/cpu_ops.h>

/*******************************************************************************
 * 'rt_svc_descs'数组保存由服务导出的运行时服务描述符，
 * 通过将它们放置在'rt_svc_descs'链接器段中。
 * 'rt_svc_descs_indices'数组保存描述符在'rt_svc_descs'数组中的索引。
 * 当SMC到达时，OEN[29:24]位和调用类型[31]位在函数ID中组合以获得
 * 'rt_svc_descs_indices'数组的索引。这给出了包含SMC处理程序的
 * 'rt_svc_descs'数组中描述符的索引。
 ******************************************************************************/
uint8_t rt_svc_descs_indices[MAX_RT_SVCS];

void __dead2 report_unhandled_exception(void);

#define RT_SVC_DECS_NUM \
	((RT_SVC_DESCS_END - RT_SVC_DESCS_START) / sizeof(rt_svc_desc_t))

static bool get_handler_for_smc_fid(uint32_t smc_fid, rt_svc_handle_t *handler)
{
	unsigned int index;
	unsigned int idx;
	const rt_svc_desc_t *rt_svc_descs;

	idx = get_unique_oen_from_smc_fid(smc_fid);
	assert(idx < MAX_RT_SVCS);
	index = rt_svc_descs_indices[idx];

	if (index >= RT_SVC_DECS_NUM)
		return false;

	rt_svc_descs = (rt_svc_desc_t *)RT_SVC_DESCS_START;
	assert(handler != NULL);
	*handler = rt_svc_descs[index].handle;
	assert(*handler != NULL);

	return true;
}

#if __aarch64__
#include <lib/extensions/ras_arch.h>

#if FFH_SUPPORT
static void ea_proceed(uint32_t ea_reason, u_register_t esr_el3,
		       cpu_context_t *ctx)
{
	/*
	 * 如果是双重故障则调用平台处理程序。当平台在较低EL中使用plat_ea_handler()处理故障时，
	 * 如果发生另一个故障，将会陷入EL3，因为平台启用了FFH_SUPPORT，从而产生双重故障场景。
	 */
	el3_state_t *state = get_el3state_ctx(ctx);
	if (read_ctx_reg(state, CTX_DOUBLE_FAULT_ESR) != 0) {
		return plat_handle_double_fault(ea_reason, esr_el3);
	}

	/*
	 * 保存CTX_DOUBLE_FAULT_ESR，这样如果在较低EL中发生另一个故障，
	 * 我们会在下次调用ea_proceed()时将其捕获为DoubleFault，同时保留原始的ESR_EL3。
	 */
	write_ctx_reg(state, CTX_DOUBLE_FAULT_ESR, esr_el3);

	/* 调用平台外部中止处理程序。 */
	plat_ea_handler(ea_reason, esr_el3, NULL, ctx,
			read_scr_el3() & SCR_NS_BIT);

	/* 清除双重故障存储 */
	write_ctx_reg(state, CTX_DOUBLE_FAULT_ESR, 0);
}

/*
 * 此函数处理来自较低EL的SError。
 *
 * 它将EA的处理委托给平台处理程序，并在成功处理EA后退出EL3
 */
void handler_lower_el_async_ea(cpu_context_t *ctx)
{
	u_register_t esr_el3 = read_esr_el3();

	if (is_feat_ras_supported()) {
		/* 应该只针对SError调用 */
		assert(EXTRACT(ESR_EC, esr_el3) == EC_SERROR);

		/*
		 * 检查实现定义的综合征。如果是这样，跳过从综合征中检查不可包含的错误类型，
		 * 因为格式未知。
		 */
		if ((esr_el3 & SERROR_IDS_BIT) != 0) {
			/* 只有当DFSC为0x11时AET才有效。如果是不可包含的错误类型，则路由到平台致命错误处理程序 */
			if (EXTRACT(EABORT_DFSC, esr_el3) == DFSC_SERROR &&
			    EXTRACT(EABORT_AET, esr_el3) ==
				    ERROR_STATUS_UET_UC) {
				return plat_handle_uncontainable_ea();
			}
		}
	}

	return ea_proceed(ERROR_EA_ASYNC, esr_el3, ctx);
}

#endif /* FFH_SUPPORT */

/*
 * 此函数处理FIQ或IRQ中断，即EL3、S-EL1和NS中断。
 */
void handler_interrupt_exception(cpu_context_t *ctx)
{
	/*
	 * 找出这是否是有效的中断类型。
	 * 如果中断控制器报告虚假中断，则返回到原来的地方。
	 */
	uint32_t type = plat_ic_get_pending_interrupt_type();
	if (type == INTR_TYPE_INVAL) {
		return;
	}

	/*
	 * 获取此中断类型的已注册处理程序。
	 * NULL返回值可能是由于以下条件之一：
	 *
	 * a. 一种类型的中断被正确路由，但未注册其类型的处理程序。
	 *
	 * b. 一种类型的中断未被正确路由，因此未注册其类型的处理程序。
	 *
	 * c. 一种类型的中断被正确路由到EL3，但在读取其挂起状态之前被取消断言。
	 *    与此同时，另一种不同类型的中断挂起，其类型被报告为挂起而不是前者。
	 *    但是，未注册此类型的处理程序。
	 *
	 * a. 和 b. 只能由于编程错误而发生。c. 的发生可能超出可信固件的控制范围。
	 * 返回此异常而不是报告错误是有意义的。
	 */
	interrupt_type_handler_t handler = get_interrupt_type_handler(type);
	if (handler == NULL) {
		return;
	}

	handler(INTR_ID_UNAVAILABLE, read_scr_el3() & SCR_NS_BIT, ctx, NULL);
}

static void smc_unknown(cpu_context_t *ctx)
{
	/*
	 * 未知SMC调用。使用SMC_UNK填充返回值并调用
	 * el3_exit()，它将在发出ERET到所需的较低EL之前恢复剩余的架构状态
	 * 即SYS、GP和PAuth寄存器(如果有的话)。
	 */
	write_ctx_reg(get_gpregs_ctx(ctx), CTX_GPREG_X0, SMC_UNK);
}

static u_register_t get_flags(uint32_t smc_fid, u_register_t scr_el3)
{
	u_register_t flags = 0;

	/* 将SCR_EL3.NS位复制到标志中以指示调用方的安全性 */
	flags |= scr_el3 & SCR_NS_BIT;
#if ENABLE_RME
	/* 将SCR_EL3.NSE位复制到标志中以指示调用方的安全性 将复制的SCR_EL3.NSE位向右移5位以为SCR_EL3.NS位创建空间。标志的第5位对应于SCR_EL3.NSE位。*/
	flags |= ((scr_el3 & SCR_NSE_BIT) >> SCR_NSE_SHIFT) << 5;
#endif /* ENABLE_RME */

	/*
	 * 根据SMCCCv1.3，调用方可以通过x0传递的SMC FID中设置SVE提示位。
	 * 将SVE提示位复制到标志中，并在传递给标准服务调度程序的smc_fid中屏蔽该位。
	 * 服务/调度程序可以使用适当的助手从标志中检索SVE提示位状态。
	 */
	flags |= smc_fid & MASK(FUNCID_SVE_HINT);

	return flags;
}

static void sync_handler(cpu_context_t *ctx, uint32_t smc_fid)
{
	u_register_t scr_el3 = read_scr_el3();
	rt_svc_handle_t handler;

	/*
	 * 根据SMCCC文档，快速SMC的位[23:17]必须为零。
	 * 其他值保留供将来使用。确保这些位为零，如果不是则报告为未知SMC。
	 */
	if (EXTRACT(FUNCID_TYPE, smc_fid) == SMC_TYPE_FAST &&
	    EXTRACT(FUNCID_FC_RESERVED, smc_fid) != 0) {
		return smc_unknown(ctx);
	}

	smc_fid &= ~MASK(FUNCID_SVE_HINT);

	/* 使用索引获取描述符 */
	if (!get_handler_for_smc_fid(smc_fid, &handler)) {
		return smc_unknown(ctx);
	}

	u_register_t x1, x2, x3, x4;
	get_smc_params_from_ctx(ctx, x1, x2, x3, x4);
	handler(smc_fid, x1, x2, x3, x4, NULL, ctx,
		get_flags(smc_fid, scr_el3));
}

void handler_sync_exception(cpu_context_t *ctx)
{
	uint32_t smc_fid = read_ctx_reg(get_gpregs_ctx(ctx), CTX_GPREG_X0);
	u_register_t esr_el3 = read_esr_el3();
	u_register_t exc_class = EXTRACT(ESR_EC, esr_el3);
	el3_state_t *state = get_el3state_ctx(ctx);

	if (exc_class == EC_AARCH32_SMC || exc_class == EC_AARCH64_SMC) {
		if (exc_class == EC_AARCH32_SMC &&
		    EXTRACT(FUNCID_CC, smc_fid) != 0) {
			return smc_unknown(ctx);
		}
		return sync_handler(ctx, smc_fid);
	} else if (exc_class == EC_AARCH64_SYS) {
		int ret = handle_sysreg_trap(
			esr_el3, ctx, get_flags(smc_fid, read_scr_el3()));

		/* 未处理的陷阱，将UNDEF注入到较低EL。仅在AArch64模式下为较低EL提供支持。 */
		if (ret == TRAP_RET_UNHANDLED) {
			if (read_spsr_el3() & MASK(SPSR_M)) {
				ERROR("Trapped an instruction from AArch32 %s mode\n",
				      get_mode_str((unsigned int)GET_M32(
					      read_spsr_el3())));
				ERROR("at address 0x%lx, reason 0x%lx\n",
				      read_elr_el3(), read_esr_el3());
				panic();
			}
			inject_undef64(ctx);
		} else if (ret == TRAP_RET_CONTINUE) {
			/* 提前PC以在指令后继续 */
			write_ctx_reg(state, CTX_ELR_EL3,
				      read_ctx_reg(state, CTX_ELR_EL3) + 4);
		} /* 否则返回到陷阱指令(重复它) */
		return;
		/* 如果支持FFH则尝试处理较低EL EA异常。 */
	} else if ((exc_class == EC_IABORT_LOWER_EL ||
		    exc_class == EC_DABORT_LOWER_EL) &&
		   ((read_ctx_reg(state, CTX_SCR_EL3) & SCR_EA_BIT) != 0UL)) {
#if FFH_SUPPORT
		/*
		 * 检查不可包含的错误类型。如果是，则路由到平台致命错误处理程序而不是通用EA处理程序。
		 */
		if (is_feat_ras_supported() &&
		    (EXTRACT(EABORT_SET, esr_el3) == ERROR_STATUS_SET_UC ||
		     EXTRACT(EABORT_DFSC, esr_el3) == SYNC_EA_FSC)) {
			return plat_handle_uncontainable_ea();
		}
		/* 为平台处理程序设置异常类别和综合征参数 */
		return ea_proceed(ERROR_EA_SYNC, esr_el3, ctx);
#endif /* FFH_SUPPORT */
	}

	/* 除上述之外的同步异常未处理 */
	report_unhandled_exception();
}
#endif /* __aarch64__ */

/*******************************************************************************
 * 在AArch32模式下调用与smc_fid对应的已注册`handle`的函数。
 ******************************************************************************/
uintptr_t handle_runtime_svc(uint32_t smc_fid, void *cookie, void *handle,
			     unsigned int flags)
{
	u_register_t x1, x2, x3, x4;
	rt_svc_handle_t handler;

	assert(handle != NULL);

	if (!get_handler_for_smc_fid(smc_fid, &handler)) {
		SMC_RET1(handle, SMC_UNK);
	}

	get_smc_params_from_ctx(handle, x1, x2, x3, x4);

	return handler(smc_fid, x1, x2, x3, x4, cookie, handle, flags);
}

/*******************************************************************************
 * 简单例程，在使用运行时服务描述符之前对其进行健全性检查
 ******************************************************************************/
static int32_t validate_rt_svc_desc(const rt_svc_desc_t *desc)
{
	if (desc == NULL) {
		return -EINVAL;
	}
	if (desc->start_oen > desc->end_oen) {
		return -EINVAL;
	}
	if (desc->end_oen >= OEN_LIMIT) {
		return -EINVAL;
	}
	if ((desc->call_type != SMC_TYPE_FAST) &&
	    (desc->call_type != SMC_TYPE_YIELD)) {
		return -EINVAL;
	}
	/* 没有初始化或处理函数的运行时服务没有意义 */
	if ((desc->init == NULL) && (desc->handle == NULL)) {
		return -EINVAL;
	}
	return 0;
}

/*******************************************************************************
 * 此函数调用运行时服务导出的描述符中的初始化例程。一旦描述符被验证，
 * 其开始和结束拥有实体编号以及调用类型被组合形成唯一的oen。
 * 唯一的oen用作'rt_svc_descs_indices'数组的索引。
 * 运行时服务描述符的索引存储在此索引处。
 ******************************************************************************/
void __init runtime_svc_init(void)
{
	int rc = 0;
	uint8_t index, start_idx, end_idx;
	rt_svc_desc_t *rt_svc_descs;

	/* 
	 * 断言检测到的服务描述符数量小于最大允许的索引数。
	 * 确保描述符范围有效且不超过系统限制。
	 */
	assert((RT_SVC_DESCS_END >= RT_SVC_DESCS_START) &&
	       (RT_SVC_DECS_NUM < MAX_RT_SVCS));

	/* 
	 * 如果没有实现任何运行时服务，则直接返回。
	 * 这是一种优化，避免不必要的处理。
	 */
	if (RT_SVC_DECS_NUM == 0U) {
		return;
	}

	/* 
	 * 将内部变量初始化为无效状态。
	 * 使用 memset 将 rt_svc_descs_indices 数组填充为 -1。
	 */
	(void)memset(rt_svc_descs_indices, -1, sizeof(rt_svc_descs_indices));

	/* 
	 * 获取运行时服务描述符数组的起始地址。
	 * 遍历所有服务描述符，逐个进行处理。
	 */
	rt_svc_descs = (rt_svc_desc_t *)RT_SVC_DESCS_START;
	for (index = 0U; index < RT_SVC_DECS_NUM; index++) {
		rt_svc_desc_t *service = &rt_svc_descs[index];

		/*
		 * 验证当前服务描述符的有效性。
		 * 如果描述符无效，则记录错误日志并触发 panic。
		 */
		rc = validate_rt_svc_desc(service);
		if (rc != 0) {
			ERROR("Invalid runtime service descriptor %p\n",
			      (void *)service);
			panic();
		}

		/*
		 * 检查当前服务是否定义了初始化函数。
		 * 如果定义了，则调用该函数进行初始化。
		 * 若初始化失败，则记录错误日志并继续处理下一个服务。
		 */
		if (service->init != NULL) {
			rc = service->init();
			if (rc != 0) {
				ERROR("Error initializing runtime service %s\n",
				      service->name);
				continue;
			}
		}

		/*
		 * 根据服务的起始和结束拥有实体编号（OEN）计算唯一索引，
		 * 并将这些索引映射到当前服务描述符的索引。
		 * 这样可以在后续处理中快速定位对应的服务。
		 */
		start_idx = (uint8_t)get_unique_oen(service->start_oen,
						    service->call_type);
		end_idx = (uint8_t)get_unique_oen(service->end_oen,
						  service->call_type);
		assert(start_idx <= end_idx);
		assert(end_idx < MAX_RT_SVCS);
		for (; start_idx <= end_idx; start_idx++) {
			rt_svc_descs_indices[start_idx] = index;
		}
	}
}