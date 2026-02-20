/*
 * Copyright (c) 2015-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdint.h>

#include <plat/common/platform.h>
#include <platform_def.h>

#include <arch.h>
#include <arch_helpers.h>
#include <bl1/bl1.h>
#include <bl2u/bl2u.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <drivers/auth/auth_mod.h>
#include <drivers/console.h>

/*******************************************************************************
 * 函数功能：BL2U主函数，负责加载SCP_BL2U（如果平台定义了SCP_BL2U_BASE）、执行平台初始化，
 *           并通过SMC调用返回到EL3。
 *
 * 参数说明：无
 *
 * 返回值说明：无
 ******************************************************************************/
void bl2u_main(void)
{
	/* 打印BL2U版本信息和构建消息 */
	NOTICE("BL2U: %s\n", build_version_string);
	NOTICE("BL2U: %s\n", build_message);

#if SCP_BL2U_BASE
	int rc;
	/* 加载后续的引导程序镜像（SCP_BL2U） */
	rc = bl2u_plat_handle_scp_bl2u();
	if (rc != 0) {
		/* 如果加载失败，则打印错误信息并触发panic */
		ERROR("Failed to load SCP_BL2U (%i)\n", rc);
		panic();
	}
#endif

	/* 在加载SCP_BL2U后执行平台初始化 */
	bl2u_platform_setup();

	/* 刷新控制台输出缓冲区 */
	console_flush();

#ifndef __aarch64__
	/*
	 * 对于AArch32状态，BL1和BL2U共享MMU设置。
	 * 由于BL2U未映射BL1区域，因此需要禁用MMU以返回BL1。
	 */
	disable_mmu_icache_secure();
#endif /* !__aarch64__ */

	/*
	 * 表示BL2U已完成，并通过SMC调用返回到正常世界（Normal World）。
	 * 注意：x1寄存器可能传递给正常世界，因此不要在此处传递任何敏感信息。
	 */
	smc(FWU_SMC_SEC_IMAGE_DONE, 0, 0, 0, 0, 0, 0, 0);
	wfi();
}