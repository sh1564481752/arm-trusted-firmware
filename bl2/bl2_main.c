/*
 * Copyright (c) 2013-2026, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <plat/common/platform.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <bl1/bl1.h>
#include <bl2/bl2.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <drivers/auth/auth_mod.h>
#include <drivers/auth/crypto_mod.h>
#include <drivers/console.h>
#include <drivers/fwu/fwu.h>
#include <lib/bootmarker_capture.h>
#include <lib/extensions/pauth.h>
#include <lib/pmf/pmf.h>

#include "bl2_private.h"

#ifdef __aarch64__
#define NEXT_IMAGE "BL31"
#else
#define NEXT_IMAGE "BL32"
#endif

#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE(bl_svc, PMF_RT_INSTR_SVC_ID, BL_TOTAL_IDS,
		     PMF_DUMP_ENABLE);
#endif

/*******************************************************************************
 * 函数功能：BL2阶段的主要入口函数，负责加载后续镜像并传递控制权给下一个引导阶段。
 * 参数说明：
 *   arg0 - 第一个通用寄存器参数，通常用于传递平台特定信息。
 *   arg1 - 第二个通用寄存器参数，通常用于传递平台特定信息。
 *   arg2 - 第三个通用寄存器参数，通常用于传递平台特定信息。
 *   arg3 - 第四个通用寄存器参数，通常用于传递平台特定信息。
 * 返回值：无。
 ******************************************************************************/
void __no_pauth bl2_main(u_register_t arg0, u_register_t arg1,
			 u_register_t arg2, u_register_t arg3)
{
	entry_point_info_t *next_bl_ep_info;

	/* 启用早期控制台（如果启用了EARLY_CONSOLE标志） */
	plat_setup_early_console();

	/* 执行早期平台相关设置 */
	bl2_early_platform_setup2(arg0, arg1, arg2, arg3);

	/* 执行剩余的通用架构设置 */
	bl2_arch_setup();

	/* 执行晚期平台相关设置 */
	bl2_plat_arch_setup();

	/* 如果支持指针认证，则根据运行级别启用指针认证 */
	if (is_feat_pauth_supported()) {
#if BL2_RUNS_AT_EL3
		pauth_init_enable_el3();
#else
		pauth_init_enable_el1();
#endif
	}

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL2_ENTRY, PMF_CACHE_MAINT);
#endif

	/* 输出BL2版本和构建信息 */
	NOTICE("BL2: %s\n", build_version_string);
	NOTICE("BL2: %s\n", build_message);

#if PSA_FWU_SUPPORT
	/* 初始化固件更新模块 */
	fwu_init();
#endif /* PSA_FWU_SUPPORT */

	/* 初始化加密模块 */
	crypto_mod_init();

	/* 初始化认证模块 */
	auth_mod_init();

	/* 初始化可信启动后端 */
	bl2_plat_mboot_init();

	/* 初始化引导源 */
	bl2_plat_preload_setup();

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL2_AUTH_START, PMF_CACHE_MAINT);
#endif

	/* 如果支持加密功能，则禁用浮点寄存器陷阱 */
	if (is_feat_crypto_supported()) {
#if BL2_RUNS_AT_EL3
		disable_fpregs_traps_el3();
#endif
	}

	/* 加载后续引导镜像 */
	next_bl_ep_info = bl2_load_images();

	/* 如果支持加密功能，则重新启用浮点寄存器陷阱 */
	if (is_feat_crypto_supported()) {
#if BL2_RUNS_AT_EL3
		enable_fpregs_traps_el3();
#endif
	}

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL2_AUTH_END, PMF_CACHE_MAINT);
#endif

	/* 完成可信启动后端操作 */
	bl2_plat_mboot_finish();

	/* 完成加密模块操作 */
	crypto_mod_finish();

#if !BL2_RUNS_AT_EL3
#ifndef __aarch64__
	/*
	 * 对于AArch32状态，BL1和BL2共享MMU设置。
	 * 鉴于BL2未映射BL1区域，需要禁用MMU以返回BL1。
	 */
	disable_mmu_icache_secure();
#endif /* !__aarch64__ */

	/*
	 * 在运行下一个引导镜像之前禁用指针认证
	 */
	if (is_feat_pauth_supported()) {
		pauth_disable_el1();
	}

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL2_EXIT, PMF_CACHE_MAINT);
#endif

	/* 刷新控制台输出 */
	console_flush();

	/*
	 * 通过SMC调用将控制权交给BL1。关于如何传递控制权给BL32（如果存在）
	 * 和BL33软件镜像的信息将作为参数传递给下一个引导镜像。
	 */
	smc(BL1_SMC_RUN_IMAGE, (unsigned long)next_bl_ep_info, 0, 0, 0, 0, 0,
	    0);
#else /* if BL2_RUNS_AT_EL3 */

	/* 输出正在引导的下一阶段镜像名称 */
	NOTICE("BL2: Booting " NEXT_IMAGE "\n");
	print_entry_point_info(next_bl_ep_info);
#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL2_EXIT, PMF_CACHE_MAINT);
#endif
	/* 刷新控制台输出 */
	console_flush();

	/*
	 * 在运行下一个引导镜像之前禁用指针认证
	 */
	if (is_feat_pauth_supported()) {
		pauth_disable_el3();
	}

	/* 运行下一个引导镜像 */
	bl2_run_next_image(next_bl_ep_info);
#endif /* BL2_RUNS_AT_EL3 */
}