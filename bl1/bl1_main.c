/*
 * Copyright (c) 2013-2026, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <plat/common/platform.h>
#include <platform_def.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <bl1/bl1.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <context.h>
#include <drivers/auth/auth_mod.h>
#include <drivers/auth/crypto_mod.h>
#include <drivers/console.h>
#include <lib/bootmarker_capture.h>
#include <lib/cpus/errata.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/extensions/pauth.h>
#include <lib/pmf/pmf.h>
#include <lib/utils.h>
#include <smccc_helpers.h>
#include <tools_share/uuid.h>

#include "bl1_private.h"

// 声明加载BL2镜像的静态函数
static void bl1_load_bl2(void);

// 如果启用了指针认证功能，声明APIAKEY变量
#if ENABLE_PAUTH
uint64_t bl1_apiakey[2];
#endif

// 如果启用运行时性能监测，注册BL服务
#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE(bl_svc, PMF_RT_INSTR_SVC_ID, BL_TOTAL_IDS, PMF_DUMP_ENABLE)
#endif

/*******************************************************************************
 * BL1主函数 - 系统启动的第一个阶段
 * 执行早期和晚期的架构及平台特定初始化
 * 查询平台以加载并运行下一个引导镜像(BL2)
 * 仅由主CPU在冷启动后调用
 ******************************************************************************/
void __no_pauth bl1_main(void)
{
	unsigned int image_id; // 存储下一个要加载的镜像ID

	/* 如果启用EARLY_CONSOLE标志，则启用早期控制台 */
	plat_setup_early_console();

	/* 执行早期平台特定设置 */
	bl1_early_platform_setup();

	/* 执行晚期平台特定设置 */
	bl1_plat_arch_setup();

	/* 初始化不会被上下文切换的寄存器 */
	cm_manage_extensions_el3(plat_my_core_pos());

	/* 当BL2在安全世界运行时，它需要一个一致的上下文 */
#if !BL2_RUNS_AT_EL3
	/* 初始化每个世界的上下文寄存器 */
	cm_manage_extensions_per_world();
#endif

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL1_ENTRY, PMF_CACHE_MAINT);
#endif

	/* 显示欢迎信息 */
	NOTICE(FIRMWARE_WELCOME_STR);
	NOTICE("BL1: %s\n", build_version_string);
	NOTICE("BL1: %s\n", build_message);

	INFO("BL1: RAM %p - %p\n", (void *)BL1_RAM_BASE, (void *)BL1_RAM_LIMIT);

	/* 打印CPU错误状态 */
	print_errata_status();

#if ENABLE_ASSERTIONS
	u_register_t val;
	/*
	 * 确保MMU/缓存和一致性已开启
	 */
#ifdef __aarch64__
	val = read_sctlr_el3(); // 读取EL3系统控制寄存器
#else
	val = read_sctlr(); // 读取系统控制寄存器
#endif
	assert((val & SCTLR_M_BIT) != 0); // 检查MMU是否启用
	assert((val & SCTLR_C_BIT) != 0); // 检查缓存是否启用
	assert((val & SCTLR_I_BIT) != 0); // 检查指令缓存是否启用
	/*
	 * 检查CTR_EL0中的缓存写回粒度(CWG)是否与平台提供的值匹配
	 */
	val = (read_ctr_el0() >> CTR_CWG_SHIFT) & CTR_CWG_MASK;
	/*
	 * 如果CWG为零，则没有CWG信息可用，但我们至少可以检查平台值是否小于架构最大值
	 */
	if (val != 0)
		assert(CACHE_WRITEBACK_GRANULE == SIZE_FROM_LOG2_WORDS(val));
	else
		assert(CACHE_WRITEBACK_GRANULE <= MAX_CACHE_LINE_SIZE);
#endif /* ENABLE_ASSERTIONS */

	/* 执行剩余的EL3通用架构设置 */
	bl1_arch_setup();

	/* 初始化加密模块 */
	crypto_mod_init();

	/* 初始化认证模块 */
	auth_mod_init();

	/* 初始化可信启动 */
	bl1_plat_mboot_init();

	/* 如果支持加密扩展，则禁用浮点寄存器陷阱 */
	if (is_feat_crypto_supported()) {
		disable_fpregs_traps_el3();
	}

	/* 在BL1中执行平台设置 */
	bl1_platform_setup();

	/* 获取下一个要加载和运行的镜像ID */
	image_id = bl1_plat_get_next_image_id();

	/*
	 * 目前我们将任何非BL2_IMAGE_ID的镜像ID解释为固件更新的开始
	 */
	if (image_id == BL2_IMAGE_ID) {
#if ENABLE_RUNTIME_INSTRUMENTATION
		PMF_CAPTURE_TIMESTAMP(bl_svc, BL1_AUTH_START, PMF_CACHE_MAINT);
#endif

		bl1_load_bl2(); // 加载BL2镜像

#if ENABLE_RUNTIME_INSTRUMENTATION
		PMF_CAPTURE_TIMESTAMP(bl_svc, BL1_AUTH_END, PMF_CACHE_MAINT);
#endif
	} else {
		NOTICE("BL1-FWU: *******FWU Process Started*******\n"); // 固件更新过程开始
	}

	/* 如果之前禁用了浮点寄存器陷阱，则重新启用 */
	if (is_feat_crypto_supported()) {
		enable_fpregs_traps_el3();
	}

	/* 清理可信启动驱动 */
	bl1_plat_mboot_finish();

	/* 完成加密模块 */
	crypto_mod_finish();

	/* 准备下一个镜像的执行环境 */
	bl1_prepare_next_image(image_id);

#if ENABLE_RUNTIME_INSTRUMENTATION
	PMF_CAPTURE_TIMESTAMP(bl_svc, BL1_EXIT, PMF_CACHE_MAINT);
#endif

	/* 刷新控制台输出 */
	console_flush();

	/* 在跳转到下一个启动镜像之前禁用指针认证 */
	if (is_feat_pauth_supported()) {
		pauth_disable_el3();
	}
}

/*******************************************************************************
 * 此函数在受信任的SRAM中定位并加载BL2原始二进制镜像
 * 由主CPU在冷启动后调用
 * TODO: 添加对替代镜像加载机制的支持，例如使用virtio/elf加载器等
 ******************************************************************************/
static void bl1_load_bl2(void)
{
	image_desc_t *desc; // 镜像描述符指针
	image_info_t *info; // 镜像信息指针
	int err; // 错误码

	/* 获取镜像描述符 */
	desc = bl1_plat_get_image_desc(BL2_IMAGE_ID);
	assert(desc != NULL);

	/* 获取镜像信息 */
	info = &desc->image_info;
	INFO("BL1: Loading BL2\n"); // 记录加载BL2的信息

	/* 处理镜像加载前的操作 */
	err = bl1_plat_handle_pre_image_load(BL2_IMAGE_ID);
	if (err != 0) {
		ERROR("Failure in pre image load handling of BL2 (%d)\n", err);
		plat_error_handler(err); // 处理错误
	}

	/* 加载并验证镜像 */
	err = load_auth_image(BL2_IMAGE_ID, info);
	if (err != 0) {
		ERROR("Failed to load BL2 firmware.\n");
		plat_error_handler(err); // 处理错误
	}

	/* 允许平台处理镜像信息 */
	err = bl1_plat_handle_post_image_load(BL2_IMAGE_ID);
	if (err != 0) {
		ERROR("Failure in post image load handling of BL2 (%d)\n", err);
		plat_error_handler(err); // 处理错误
	}

	NOTICE("BL1: Booting BL2\n"); // 通知用户正在启动BL2
}

/*******************************************************************************
 * 在移交控制权给下一个BL之前调用的函数，用于通知用户启动进度
 * 在调试模式下，还打印有关BL镜像执行上下文的详细信息
 ******************************************************************************/
void bl1_print_next_bl_ep_info(const entry_point_info_t *bl_ep_info)
{
#ifdef __aarch64__
	NOTICE("BL1: Booting BL31\n"); // AArch64模式下启动BL31
#else
	NOTICE("BL1: Booting BL32\n"); // AArch32模式下启动BL32
#endif /* __aarch64__ */
	print_entry_point_info(bl_ep_info); // 打印入口点信息
}

// 如果定义了SPIN_ON_BL1_EXIT，则提供调试循环消息函数
#if SPIN_ON_BL1_EXIT
void print_debug_loop_message(void)
{
	NOTICE("BL1: Debug loop, spinning forever\n");
	NOTICE("BL1: Please connect the debugger to continue\n");
}
#endif

/*******************************************************************************
 * 服务BL1 SMC调用的顶级处理程序
 ******************************************************************************/
u_register_t bl1_smc_handler(unsigned int smc_fid, u_register_t x1,
			     u_register_t x2, u_register_t x3, u_register_t x4,
			     void *cookie, void *handle, unsigned int flags)
{
	/* BL1服务UUID */
	DEFINE_SVC_UUID2(bl1_svc_uid, U(0xd46739fd), 0xcb72, 0x9a4d, 0xb5, 0x75,
			 0x67, 0x15, 0xd6, 0xf4, 0xbb, 0x4a);

#if TRUSTED_BOARD_BOOT
	/*
	 * 将FWU调用分派给FWU SMC处理程序并返回其返回值
	 */
	if (is_fwu_fid(smc_fid)) {
		return bl1_fwu_smc_handler(smc_fid, x1, x2, x3, x4, cookie,
					   handle, flags);
	}
#endif

	// 根据SMC功能ID处理不同的调用
	switch (smc_fid) {
	case BL1_SMC_CALL_COUNT:
		SMC_RET1(handle, BL1_NUM_SMC_CALLS); // 返回SMC调用数量

	case BL1_SMC_UID:
		SMC_UUID_RET(handle, bl1_svc_uid); // 返回服务UUID

	case BL1_SMC_VERSION:
		SMC_RET1(handle,
			 BL1_SMC_MAJOR_VER | BL1_SMC_MINOR_VER); // 返回版本信息

	default:
		WARN("Unimplemented BL1 SMC Call: 0x%x\n",
		     smc_fid); // 警告未实现的调用
		SMC_RET1(handle, SMC_UNK); // 返回未知调用错误
	}
}

// AArch64架构的SMC包装函数
#if __aarch64__
u_register_t bl1_smc_wrapper_aarch64(cpu_context_t *ctx)
{
	u_register_t x1, x2, x3, x4;
	unsigned int smc_fid, flags;
	gp_regs_t *gpregs = get_gpregs_ctx(ctx);

	// 从上下文中读取参数
	smc_fid = read_ctx_reg(gpregs, CTX_GPREG_X0);
	x1 = read_ctx_reg(gpregs, CTX_GPREG_X1);
	x2 = read_ctx_reg(gpregs, CTX_GPREG_X2);
	x3 = read_ctx_reg(gpregs, CTX_GPREG_X3);
	x4 = read_ctx_reg(gpregs, CTX_GPREG_X4);

	/* 将SCR_EL3.NS位复制到标志中以指示调用者的安全状态 */
	flags = read_scr_el3() & SCR_NS_BIT;

	// 调用主SMC处理函数
	return bl1_smc_handler(smc_fid, x1, x2, x3, x4, NULL, ctx, flags);
}
#else
/*******************************************************************************
 * BL1 SMC包装函数。此函数仅在AArch32模式下使用，以确保调用bl1_smc_handler时的ABI兼容性
 ******************************************************************************/
u_register_t bl1_smc_wrapper_aarch32(uint32_t smc_fid, void *cookie,
				     void *handle, unsigned int flags)
{
	u_register_t x1, x2, x3, x4;

	assert(handle != NULL);

	// 从上下文中获取SMC参数
	get_smc_params_from_ctx(handle, x1, x2, x3, x4);
	return bl1_smc_handler(smc_fid, x1, x2, x3, x4, cookie, handle, flags);
}
#endif