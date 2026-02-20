/*
 * Copyright (c) 2013-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>

#include <plat/common/platform.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <bl31/ehf.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <common/feat_detect.h>
#include <common/runtime_svc.h>
#include <drivers/arm/dsu.h>
#include <drivers/arm/gic.h>
#include <drivers/console.h>
#include <lib/bootmarker_capture.h>
#include <lib/el3_runtime/context_debug.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/extensions/pauth.h>
#include <lib/gpt_rme/gpt_rme.h>
#include <lib/pmf/pmf.h>
#include <lib/runtime_instr.h>
#include <lib/xlat_tables/xlat_mmu_helpers.h>
#include <services/std_svc.h>

#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE_SMC(rt_instr_svc, PMF_RT_INSTR_SVC_ID, RT_INSTR_TOTAL_IDS,
			 PMF_STORE_ENABLE)
#endif

#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE(bl_svc, PMF_RT_INSTR_SVC_ID, BL_TOTAL_IDS, PMF_DUMP_ENABLE)
#endif

/*******************************************************************************
 * 此函数指针用于初始化BL32镜像。它由SPD在设置好SP执行所需的所有必要条件后，
 * 通过调用bl31_register_bl32_init进行初始化。
 * 在SPD和SP都不存在的情况下，或者当SPD发现无法执行SP时，此指针保持为NULL
 ******************************************************************************/
static int32_t (*bl32_init)(void);

/*****************************************************************************
 * 用于在启用RME时初始化RMM的函数
 *****************************************************************************/
#if ENABLE_RME
static int32_t (*rmm_init)(void);
#endif

/*******************************************************************************
 * 变量用于指示BL31之后要执行的下一个镜像是BL33（非安全，默认）还是BL32（安全）。
 ******************************************************************************/
static uint32_t next_image_type = (uint32_t)NON_SECURE;

#ifdef SUPPORT_UNKNOWN_MPID
/*
 * 用于标识是否检测到不支持的MPID的标志。为了避免将其放置在.bss段中，
 * 它被初始化为非零值，这样可以避免系统启动期间潜在的WAW（写后写）冒险。
 * */
volatile uint32_t unsupported_mpid_flag = 1;
#endif

/*
 * 获取特定ARM标准服务的参数。
 *
 * 参数:
 *   svc_mask - 服务掩码，用于标识请求的服务类型。
 *
 * 返回值:
 *   返回指向PSCI库参数结构体的指针。
 */
uintptr_t get_arm_std_svc_args(unsigned int svc_mask)
{
	/* Setup the arguments for PSCI Library */
	DEFINE_STATIC_PSCI_LIB_ARGS_V1(psci_args, bl31_warm_entrypoint);

	/* PSCI是唯一实现的ARM标准服务 */
	assert(svc_mask == PSCI_FID_MASK);

	return (uintptr_t)&psci_args;
}

/*******************************************************************************
 * 初始化所有BL31辅助库。
 ******************************************************************************/
static void __init bl31_lib_init(void)
{
	cm_init();
}

/*******************************************************************************
 * BL31负责在将控制权传递给引导加载程序或操作系统之前，
 * 为主CPU设置运行时服务。此函数调用runtime_svc_init()来初始化所有已注册的运行时服务。
 * 运行时服务会设置足够的上下文，以便核心切换到下一个异常级别。
 * 当此函数返回时，核心将通过ERET切换到编程的异常级别。
 *
 * 参数:
 *   arg0 - 第一个通用寄存器参数。
 *   arg1 - 第二个通用寄存器参数。
 *   arg2 - 第三个通用寄存器参数。
 *   arg3 - 第四个通用寄存器参数。
 ******************************************************************************/
void __no_pauth bl31_main(u_register_t arg0, u_register_t arg1,
			  u_register_t arg2, u_register_t arg3)
{
	unsigned int core_pos = plat_my_core_pos();

	/* 启用早期控制台（如果启用了EARLY_CONSOLE标志） */
	plat_setup_early_console();

	/* 执行平台特定的早期设置 */
	bl31_early_platform_setup2(arg0, arg1, arg2, arg3);

	/* 执行平台特定的后期设置 */
	bl31_plat_arch_setup();

#if FEATURE_DETECTION
	/* 检测编译期间启用的功能是否受PE支持 */
	detect_arch_features(core_pos);
#endif /* FEATURE_DETECTION */

	/* 打印所有安全状态分配的上下文内存使用情况 */
	report_ctx_memory_usage();

	/* 初始化在整个核心生命周期内不会更改的寄存器 */
	cm_manage_extensions_el3(core_pos);

	/* 初始化每世界上下文寄存器 */
	cm_manage_extensions_per_world();

	NOTICE("BL31: %s\n", build_version_string);
	NOTICE("BL31: %s\n", build_message);

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL31_ENTRY, PMF_CACHE_MAINT);
#endif

#ifdef SUPPORT_UNKNOWN_MPID
	if (unsupported_mpid_flag == 0) {
		NOTICE("Unsupported MPID detected!\n");
	}
#endif

	/* 在BL31中执行平台设置 */
	bl31_platform_setup();

#if USE_DSU_DRIVER
	dsu_driver_init(&plat_dsu_data);
#endif

#if USE_GIC_DRIVER
	/*
	 * 初始化GIC驱动以及每个CPU和全局接口。
	 * 平台有机会进行特定初始化。
	 */
	gic_init(core_pos);
	gic_pcpu_init(core_pos);
	gic_cpuif_enable(core_pos);
#endif /* USE_GIC_DRIVER */

	/* 初始化辅助库 */
	bl31_lib_init();

#if EL3_EXCEPTION_HANDLING
	INFO("BL31: Initialising Exception Handling Framework\n");
	ehf_init();
#endif

	/* 初始化运行时服务，例如PSCI */
	INFO("BL31: Initializing runtime services\n");
	runtime_svc_init();

	/*
	 * 主CPU上的所有冷启动操作已完成。现在需要决定下一个镜像以及如何执行它。
	 * 如果存在SPD运行时服务，它希望首先将控制权传递给S-EL1中的BL32。
	 * 在这种情况下，SPD将注册一个函数来初始化BL32，在其中负责进入S-EL1并返回控制权给bl31_main。
	 * 类似地，如果启用了RME并且注册了初始化RMM的函数，则控制权将转移到R-EL2中的RMM。
	 * 完成后，我们可以正常准备进入BL33。
	 */

	/*
	 * 如果SPD已注册初始化钩子，则调用它。
	 */
	if (bl32_init != NULL) {
		INFO("BL31: Initializing BL32\n");

		console_flush();
		int32_t rc = (*bl32_init)();

		if (rc == 0) {
			WARN("BL31: BL32 initialization failed\n");
		}
	}

	/*
	 * 如果启用了RME且注册了初始化钩子，则在R-EL2中初始化RMM。
	 */
#if ENABLE_RME
	if (rmm_init != NULL) {
		INFO("BL31: Initializing RMM\n");

		console_flush();
		int32_t rc = (*rmm_init)();

		if (rc == 0) {
			WARN("BL31: RMM initialization failed\n");
		}
	}
#endif

	/*
	 * 我们准备好进入下一个EL。准备在下一次ERET之后进入对应所需安全状态的镜像。
	 */
	bl31_prepare_next_image_entry();

	/*
	 * 在从BL31退出冷启动之前执行任何平台特定的运行时设置
	 */
	bl31_plat_runtime_setup();

#if ENABLE_RUNTIME_INSTRUMENTATION
	console_flush();
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL31_EXIT, PMF_CACHE_MAINT);
#endif

	console_flush();
	console_switch_state(CONSOLE_FLAG_RUNTIME);
}

/*
 * 处理热启动流程。
 *
 * 参数:
 *   无显式参数，但依赖于平台特定的核心位置信息。
 */
void __no_pauth bl31_warmboot(void)
{
	unsigned int core_pos = plat_my_core_pos();

#if FEATURE_DETECTION
	/* 检测编译期间启用的功能是否受PE支持 */
	detect_arch_features(core_pos);
#endif /* FEATURE_DETECTION */

	/*
	 * 我们即将启用MMU并参与PSCI状态协调。
	 *
	 * PSCI实现会调用平台例程以使CPU能够参与一致性。
	 * 在某些系统上，如果没有适当的平台特定编程，CPU无法在缓存启用的情况下参与一致性，
	 * 因此即使在启用MMU后也要保持数据缓存禁用。
	 *
	 * 在具有硬件辅助一致性的系统或单集群平台上，不需要此类平台特定编程即可进入一致性，
	 * 缓存也没有理由被禁用。
	 */
#if HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY
	bl31_plat_enable_mmu(0);
#else
	bl31_plat_enable_mmu(DISABLE_DCACHE);
#endif

	/* 初始化在整个核心生命周期内不会更改的寄存器 */
	cm_manage_extensions_el3(core_pos);

#if ENABLE_RME
	/*
	 * 在热启动时，RAM中的GPT数据结构已经初始化，
	 * 但此CPU的系统寄存器需要初始化。
	 * 注意：GPT访问由GPCCR中的控制属性管理，并不依赖于SCR_EL3.C位。
	 */
	if (gpt_enable() != 0) {
		panic();
	}
#endif

/* 为每个启动核心启用DSU驱动 */
#if USE_DSU_DRIVER
	dsu_driver_init(&plat_dsu_data);
#endif

	psci_warmboot_entrypoint(core_pos);
}

/*******************************************************************************
 * 访问器函数帮助运行时服务决定BL31之后应执行哪个镜像。
 * 默认情况下是BL33或非安全引导加载程序镜像，
 * 但安全负载调度器可以通过请求首先进入BL32（安全负载）来覆盖此行为。
 * 如果这样做，它应该使用相同的API在BL32初始化完成后编程进入BL33。
 ******************************************************************************/
void bl31_set_next_image_type(uint32_t security_state)
{
	assert(sec_state_is_valid(security_state));
	next_image_type = security_state;
}

static uint32_t bl31_get_next_image_type(void)
{
	return next_image_type;
}

/*******************************************************************************
 * 此函数编程EL3寄存器并执行其他设置以在下一次ERET后进入BL31之后的下一个镜像。
 ******************************************************************************/
void __init bl31_prepare_next_image_entry(void)
{
	const entry_point_info_t *next_image_info;
	uint32_t image_type;

#if CTX_INCLUDE_AARCH32_REGS
	/*
	 * 确保在仅支持AArch64的平台上未设置保存AArch32系统寄存器到CPU上下文的构建标志。
	 */
	if (el_implemented(1) == EL_IMPL_A64ONLY) {
		ERROR("EL1 supports AArch64-only. Please set build flag "
		      "CTX_INCLUDE_AARCH32_REGS = 0\n");
		panic();
	}
#endif

	/* 确定要执行的下一个镜像 */
	image_type = bl31_get_next_image_type();

	/* 编程EL3寄存器以启用进入下一个EL */
	next_image_info = bl31_plat_get_next_image_ep_info(image_type);
	assert(next_image_info != NULL);
	assert(image_type == GET_SECURITY_STATE(next_image_info->h.attr));

	INFO("BL31: Preparing for EL3 exit to %s world\n",
	     (image_type == SECURE) ? "secure" : "normal");
	print_entry_point_info(next_image_info);
	cm_init_my_context(next_image_info);

	/*
	* 如果我们正在进入非安全世界，请使用'cm_prepare_el3_exit_ns'退出。
	*/
	if (image_type == NON_SECURE) {
		cm_prepare_el3_exit_ns();
	} else {
		cm_prepare_el3_exit(image_type);
	}
}

/*******************************************************************************
 * 此函数初始化指向BL32初始化函数的指针。
 * 预期由SPD在其完成所有初始化后调用。
 ******************************************************************************/
void bl31_register_bl32_init(int32_t (*func)(void))
{
	bl32_init = func;
}

#if ENABLE_RME
/*******************************************************************************
 * 此函数初始化指向RMM初始化函数的指针。
 * 预期由RMMD在其完成所有初始化后调用。
 ******************************************************************************/
void bl31_register_rmm_init(int32_t (*func)(void))
{
	rmm_init = func;
}
#endif