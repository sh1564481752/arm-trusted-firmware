/*
 * 版权所有 (c) 2013-2025, Arm Limited 及其贡献者。保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * 这是安全负载调度器(SPD)。该调度器旨在作为安全监视器的插件组件注册为运行时服务。
 * SPD 被期望作为在安全 EL1 中执行的安全负载(SP)的功能扩展。安全监视器将把所有针对
 * 受信任操作系统/应用程序范围的 SMC 委托给调度器。SPD 将要么本地处理请求，
 * 要么将其委托给安全负载。它还负责初始化和维护与 SP 的通信。
 ******************************************************************************/
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>

#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/coreboot.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/optee_utils.h>
#if TRANSFER_LIST
#include <transfer_list.h>
#endif
#include <lib/xlat_tables/xlat_tables_v2.h>
#if OPTEE_ALLOW_SMC_LOAD
#include <libfdt.h>
#endif /* OPTEE_ALLOW_SMC_LOAD */
#include <plat/common/platform.h>

#include <services/oem/chromeos/widevine_smc_handlers.h>
#include <tools_share/uuid.h>

#include "opteed_private.h"
#include "teesmc_opteed.h"

#if OPTEE_ALLOW_SMC_LOAD
static struct transfer_list_header __maybe_unused *bl31_tl;
#endif

/*******************************************************************************
 * OPTEE 中入口向量表的地址。它在冷启动后在主核上初始化一次。
 ******************************************************************************/
struct optee_vectors *optee_vector_table;

/*******************************************************************************
 * 用于跟踪每个 CPU 的 OPTEE 状态的数组
 ******************************************************************************/
optee_context_t opteed_sp_context[OPTEED_CORE_COUNT];
uint32_t opteed_rw;

#if OPTEE_ALLOW_SMC_LOAD
static bool opteed_allow_load;
/* OP-TEE 镜像加载服务 UUID */
DEFINE_SVC_UUID2(optee_image_load_uuid, 0xb1eafba3, 0x5d31, 0x4612, 0xb9, 0x06,
		 0xc4, 0xc7, 0xa4, 0xbe, 0x3c, 0xc0);

static uint64_t dual32to64(uint32_t high, uint32_t low)
{
	return ((uint64_t)high << 32) | low;
}

#define OPTEED_FDT_SIZE 1024
static uint8_t fdt_buf[OPTEED_FDT_SIZE] __aligned(CACHE_WRITEBACK_GRANULE);

#else
static int32_t opteed_init(void);
#endif
/*******************************************************************************
 * 这个函数是由 OPTEED 为 S-EL1 中断注册的处理程序。它验证中断并在成功时安排进入
 * OPTEE 的 'optee_fiq_entry()' 来处理中断。
 ******************************************************************************/
static uint64_t opteed_sel1_interrupt_handler(uint32_t id, uint32_t flags,
					      void *handle, void *cookie)
{
	uint32_t linear_id;
	optee_context_t *optee_ctx;

#if OPTEE_ALLOW_SMC_LOAD
	if (optee_vector_table == NULL) {
		/* OPTEE 尚未加载，忽略此中断 */
		SMC_RET0(handle);
	}
#endif

	/* 检查生成异常时的安全状态 */
	assert(get_interrupt_src_ss(flags) == NON_SECURE);

	/* 对指向此 CPU 上下文的指针进行健全性检查 */
	assert(handle == cm_get_context(NON_SECURE));

	/* 在进入 OPTEE 之前保存非安全上下文 */
	cm_el1_sysregs_context_save(NON_SECURE);

	/* 获取对此 CPU 的 OPTEE 上下文的引用 */
	linear_id = plat_my_core_pos();
	optee_ctx = &opteed_sp_context[linear_id];
	assert(&optee_ctx->cpu_ctx == cm_get_context(SECURE));

	cm_set_elr_el3(SECURE, (uint64_t)&optee_vector_table->fiq_entry);
	cm_el1_sysregs_context_restore(SECURE);
	cm_set_next_eret_context(SECURE);

	/*
	 * 告诉 OPTEE 它必须处理一个 FIQ（同步地）。
	 * 同时传递在正常世界中生成中断的指令以用于调试目的。
	 * 从 ELR_EL3 检索此地址是安全的，因为安全上下文在 el3_exit() 之前不会生效。
	 */
	SMC_RET1(&optee_ctx->cpu_ctx, read_elr_el3());
}

/*
 * 为在非安全状态下执行的代码生成 S-EL1 中断时注册中断处理程序。
 * 如果注册失败则会发生恐慌。
 */
static void register_opteed_interrupt_handler(void)
{
	u_register_t flags;
	uint64_t rc;

	flags = 0;
	set_interrupt_rm_flag(flags, NON_SECURE);
	rc = register_interrupt_type_handler(
		INTR_TYPE_S_EL1, opteed_sel1_interrupt_handler, flags);
	if (rc)
		panic();
}

/*******************************************************************************
 * OPTEE 调度器设置。OPTEED 找出 OPTEE 入口点和类型（aarch32/aarch64）
 * （如果尚未知道）并初始化进入 OPTEE 进行初始化的上下文。
 ******************************************************************************/
static int32_t opteed_setup(void)
{
#if OPTEE_ALLOW_SMC_LOAD
	opteed_allow_load = true;
	INFO("延迟 OP-TEE 设置直到我们收到加载它的 SMC 调用\n");
	/*
	 * 我们现在必须注册中断处理程序，这样在启动 Linux 内核后就不会改变中断优先级。
	 */
	register_opteed_interrupt_handler();
	return 0;
#else
	entry_point_info_t *optee_ep_info;
	uint32_t linear_id;
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	struct transfer_list_header __maybe_unused *tl = NULL;
	struct transfer_list_entry __maybe_unused *te = NULL;
	void __maybe_unused *dt = NULL;

	linear_id = plat_my_core_pos();

	/*
	 * 获取关于安全负载(BL32)镜像的信息。它的缺失是致命故障。
	 * TODO: 添加支持以有条件地包含 SPD 服务
	 */
	optee_ep_info = bl31_plat_get_next_image_ep_info(SECURE);
	if (optee_ep_info == NULL) {
		WARN("BL2 引导加载程序未提供 OPTEE，正在无 OPTEE 初始化的情况下引导设备。"
		     "针对 OPTEE 的 SMC 将返回 SMC_UNK\n");
		return 1;
	}

	/*
	 * 如果 SP 没有有效的入口点，我们返回一个非零值表示初始化服务失败。
	 * 我们在不注册任何处理程序的情况下退出
	 */
	if (optee_ep_info->pc == 0U) {
		return 1;
	}

#if TRANSFER_LIST
	tl = (void *)optee_ep_info->args.arg3;

	if (transfer_list_check_header(tl)) {
		te = transfer_list_find(tl, TL_TAG_FDT);
		dt = transfer_list_entry_data(te);

		opteed_rw = GET_RW(optee_ep_info->spsr);
		if (opteed_rw == OPTEE_AARCH64) {
			if (optee_ep_info->args.arg1 !=
			    TRANSFER_LIST_HANDOFF_X1_VALUE(
				    REGISTER_CONVENTION_VERSION))
				return 1;

			arg0 = (uint64_t)dt;
			arg2 = 0;
		} else {
			if (optee_ep_info->args.arg1 !=
			    TRANSFER_LIST_HANDOFF_R1_VALUE(
				    REGISTER_CONVENTION_VERSION))
				return 1;

			arg0 = 0;
			arg2 = (uint64_t)dt;
		}

		arg1 = optee_ep_info->args.arg1;
		arg3 = optee_ep_info->args.arg3;

	} else
#endif /* TRANSFER_LIST */
	{
		/* 默认移交参数 */
		opteed_rw = optee_ep_info->args.arg0;
		arg0 = optee_ep_info->args.arg1; /* opteed_pageable_part */
		arg1 = optee_ep_info->args.arg2; /* opteed_mem_limit */
		arg2 = optee_ep_info->args.arg3; /* dt_addr */
		arg3 = 0;
	}

	opteed_init_optee_ep_state(optee_ep_info, opteed_rw, optee_ep_info->pc,
				   arg0, arg1, arg2, arg3,
				   &opteed_sp_context[linear_id]);

	/*
	 * 所有 OPTEED 初始化完成。现在向 BL31 注册我们的初始化函数以进行延迟调用
	 */
	bl31_register_bl32_init(&opteed_init);

	return 0;
#endif /* OPTEE_ALLOW_SMC_LOAD */
}

/*******************************************************************************
 * 此函数在冷启动后首次将控制权传递给 OPTEE 镜像(BL32)到主 CPU。
 * 它假定 opteed_setup() 已经创建了一个有效的安全上下文，可以直接使用。
 * 它还假定 PSCI 已经初始化了一个有效的非安全上下文，因此不需要保存和恢复任何
 * 非安全状态。此函数执行同步进入 OPTEE。OPTEE 通过 SMC 将控制权传回此例程。
 * 成功时返回非零值，失败时返回零。
 ******************************************************************************/
static int32_t
opteed_init_with_entry_point(entry_point_info_t *optee_entry_point)
{
	uint32_t linear_id = plat_my_core_pos();
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];
	uint64_t rc;
	assert(optee_entry_point);

	cm_init_my_context(optee_entry_point);

	/*
	 * 安排进入 OPTEE。它将通过 OPTEE_ENTRY_DONE 情况返回
	 */
	rc = opteed_synchronous_sp_entry(optee_ctx);
	assert(rc != 0);

	return rc;
}

#if !OPTEE_ALLOW_SMC_LOAD
static int32_t opteed_init(void)
{
	entry_point_info_t *optee_entry_point;
	/*
	 * 获取关于 OP-TEE(BL32)镜像的信息。它的缺失是致命故障。
	 */
	optee_entry_point = bl31_plat_get_next_image_ep_info(SECURE);
	return opteed_init_with_entry_point(optee_entry_point);
}
#endif /* !OPTEE_ALLOW_SMC_LOAD */

#if OPTEE_ALLOW_SMC_LOAD
#if COREBOOT
/*
 * 向设备树添加带有 coreboot 表信息的固件/coreboot 节点。
 * 成功或没有 coreboot 表信息时返回零；否则返回错误代码。
 */
static int add_coreboot_node(void *fdt)
{
	int ret;
	uint64_t coreboot_table_addr;
	uint32_t coreboot_table_size;
	struct {
		uint64_t addr;
		uint32_t size;
	} reg_node;
	coreboot_get_table_location(&coreboot_table_addr, &coreboot_table_size);
	if (!coreboot_table_addr || !coreboot_table_size) {
		WARN("无法获取设备树的 coreboot 表位置");
		return 0;
	}
	ret = fdt_begin_node(fdt, "firmware");
	if (ret)
		return ret;

	ret = fdt_property(fdt, "ranges", NULL, 0);
	if (ret)
		return ret;

	ret = fdt_begin_node(fdt, "coreboot");
	if (ret)
		return ret;

	ret = fdt_property_string(fdt, "compatible", "coreboot");
	if (ret)
		return ret;

	reg_node.addr = cpu_to_fdt64(coreboot_table_addr);
	reg_node.size = cpu_to_fdt32(coreboot_table_size);
	ret = fdt_property(fdt, "reg", &reg_node,
			   sizeof(uint64_t) + sizeof(uint32_t));
	if (ret)
		return ret;

	ret = fdt_end_node(fdt);
	if (ret)
		return ret;

	return fdt_end_node(fdt);
}
#endif /* COREBOOT */

#if CROS_WIDEVINE_SMC
/*
 * 向设备树添加带有 widevine 表信息的选项/widevine 节点。
 * 成功或没有 widevine 表信息时返回零；否则返回错误代码。
 */
static int add_options_widevine_node(void *fdt)
{
	int ret;

	ret = fdt_begin_node(fdt, "options");
	if (ret)
		return ret;

	ret = fdt_begin_node(fdt, "op-tee");
	if (ret)
		return ret;

	ret = fdt_begin_node(fdt, "widevine");
	if (ret)
		return ret;

	if (cros_oem_tpm_auth_pk.length) {
		ret = fdt_property(fdt, "tcg,tpm-auth-public-key",
				   cros_oem_tpm_auth_pk.buffer,
				   cros_oem_tpm_auth_pk.length);
		if (ret)
			return ret;
	}

	if (cros_oem_huk.length) {
		ret = fdt_property(fdt, "op-tee,hardware-unique-key",
				   cros_oem_huk.buffer, cros_oem_huk.length);
		if (ret)
			return ret;
	}

	if (cros_oem_rot.length) {
		ret = fdt_property(fdt,
				   "google,widevine-root-of-trust-ecc-p256",
				   cros_oem_rot.buffer, cros_oem_rot.length);
		if (ret)
			return ret;
	}

	ret = fdt_end_node(fdt);
	if (ret)
		return ret;

	ret = fdt_end_node(fdt);
	if (ret)
		return ret;

	return fdt_end_node(fdt);
}
#endif /* CROS_WIDEVINE_SMC */

/*
 * 创建用于传递给 OP-TEE 的设备树。目前填充了 coreboot 表地址。
 * 成功时返回 0，否则返回错误代码。
 */
static int create_opteed_dt(void)
{
	int ret;

	ret = fdt_create(fdt_buf, OPTEED_FDT_SIZE);
	if (ret)
		return ret;

	ret = fdt_finish_reservemap(fdt_buf);
	if (ret)
		return ret;

	ret = fdt_begin_node(fdt_buf, "");
	if (ret)
		return ret;

#if COREBOOT
	ret = add_coreboot_node(fdt_buf);
	if (ret)
		return ret;
#endif /* COREBOOT */

#if CROS_WIDEVINE_SMC
	ret = add_options_widevine_node(fdt_buf);
	if (ret)
		return ret;
#endif /* CROS_WIDEVINE_SMC */

	ret = fdt_end_node(fdt_buf);
	if (ret)
		return ret;

	return fdt_finish(fdt_buf);
}

#if TRANSFER_LIST
static int32_t create_smc_tl(const void *fdt, uint32_t fdt_sz)
{
	bl31_tl = transfer_list_init((void *)(uintptr_t)FW_HANDOFF_BASE,
				     FW_HANDOFF_SIZE);
	if (!bl31_tl) {
		ERROR("在 0x%lx 处初始化传输列表失败\n",
		      (unsigned long)FW_HANDOFF_BASE);
		return -1;
	}

	if (!transfer_list_add(bl31_tl, TL_TAG_FDT, fdt_sz, fdt)) {
		return -1;
	}
	return 0;
}
#endif

/*******************************************************************************
 * 此函数负责处理通过非安全 SMC 调用加载 OP-TEE 二进制镜像的 SMC。
 * 它以负载的大小和物理地址作为参数。
 ******************************************************************************/
static int32_t opteed_handle_smc_load(uint64_t data_size, uint64_t data_pa)
{
	uintptr_t data_va = data_pa;
	uint64_t mapped_data_pa;
	uintptr_t mapped_data_va;
	uint64_t data_map_size;
	int32_t rc;
	optee_header_t *image_header;
	uint8_t *image_ptr;
	uint64_t target_pa;
	uint64_t target_end_pa;
	uint64_t image_pa;
	uintptr_t image_va;
	optee_image_t *curr_image;
	uintptr_t target_va;
	uint64_t target_size;
	entry_point_info_t optee_ep_info;
	uint32_t linear_id = plat_my_core_pos();
	uint64_t dt_addr = 0;
	uint64_t arg0 = 0;
	uint64_t arg1 = 0;
	uint64_t arg2 = 0;
	uint64_t arg3 = 0;

	mapped_data_pa = page_align(data_pa, DOWN);
	mapped_data_va = mapped_data_pa;
	data_map_size = page_align(data_size + (mapped_data_pa - data_pa), UP);

	/*
	 * 我们此时仍然信任非安全世界，因此不验证传入的地址。
	 */
	rc = mmap_add_dynamic_region(mapped_data_pa, mapped_data_va,
				     data_map_size, MT_MEMORY | MT_RO | MT_NS);
	if (rc != 0) {
		return rc;
	}

	image_header = (optee_header_t *)data_va;
	if (image_header->magic != TEE_MAGIC_NUM_OPTEE ||
	    image_header->version != 2 || image_header->nb_images != 1) {
		mmap_remove_dynamic_region(mapped_data_va, data_map_size);
		return -EINVAL;
	}

	image_ptr = (uint8_t *)data_va + sizeof(optee_header_t) +
		    sizeof(optee_image_t);
	if (image_header->arch == 1) {
		opteed_rw = OPTEE_AARCH64;
	} else {
		opteed_rw = OPTEE_AARCH32;
	}

	curr_image = &image_header->optee_image_list[0];
	image_pa =
		dual32to64(curr_image->load_addr_hi, curr_image->load_addr_lo);
	image_va = image_pa;
	target_end_pa = image_pa + curr_image->size;

	/* 现在也映射我们要复制到的内存。 */
	target_pa = page_align(image_pa, DOWN);
	target_va = target_pa;
	target_size = page_align(target_end_pa, UP) - target_pa;

	rc = mmap_add_dynamic_region(target_pa, target_va, target_size,
				     MT_MEMORY | MT_RW | MT_SECURE);
	if (rc != 0) {
		mmap_remove_dynamic_region(mapped_data_va, data_map_size);
		return rc;
	}

	INFO("通过 SMC 加载 OP-TEE: 大小 %d 地址 0x%" PRIx64 "\n",
	     curr_image->size, image_va);

	memcpy((void *)image_va, image_ptr, curr_image->size);
	flush_dcache_range(target_pa, target_size);

	mmap_remove_dynamic_region(mapped_data_va, data_map_size);
	mmap_remove_dynamic_region(target_va, target_size);

	/* 保存非安全状态 */
	cm_el1_sysregs_context_save(NON_SECURE);

	rc = create_opteed_dt();
	if (rc) {
		ERROR("设备树创建失败 %d\n", rc);
		return rc;
	}
	dt_addr = (uint64_t)fdt_buf;
	flush_dcache_range(dt_addr, OPTEED_FDT_SIZE);

#if TRANSFER_LIST
	if (!create_smc_tl((void *)dt_addr, OPTEED_FDT_SIZE)) {
		struct transfer_list_entry *te = NULL;
		void *dt = NULL;

		te = transfer_list_find(bl31_tl, TL_TAG_FDT);
		dt = transfer_list_entry_data(te);

		if (opteed_rw == OPTEE_AARCH64) {
			arg0 = (uint64_t)dt;
			arg1 = TRANSFER_LIST_HANDOFF_X1_VALUE(
				REGISTER_CONVENTION_VERSION);
			arg2 = 0;
		} else {
			arg0 = 0;
			arg1 = TRANSFER_LIST_HANDOFF_R1_VALUE(
				REGISTER_CONVENTION_VERSION);
			arg2 = (uint64_t)dt;
		}

		arg3 = (uint64_t)bl31_tl;
	} else
#endif /* TRANSFER_LIST */
	{
		/* 默认移交参数 */
		arg2 = dt_addr;
	}

	opteed_init_optee_ep_state(&optee_ep_info, opteed_rw, image_pa, arg0,
				   arg1, arg2, arg3,
				   &opteed_sp_context[linear_id]);
	if (opteed_init_with_entry_point(&optee_ep_info) == 0) {
		rc = -EFAULT;
	}

	/* 恢复非安全状态 */
	cm_el1_sysregs_context_restore(NON_SECURE);
	cm_set_next_eret_context(NON_SECURE);

	return rc;
}
#endif /* OPTEE_ALLOW_SMC_LOAD */

/*******************************************************************************
 * 此函数负责处理来自非安全状态的信任操作系统/应用程序范围内的所有 SMC，
 * 如 SMC 调用约定文档中定义的那样。它还负责与安全负载通信以委派工作并将结果
 * 返回到非安全状态。最后，它还将返回 OPTEE 完成分配给它的工作所需的所有信息。
 ******************************************************************************/
static uintptr_t opteed_smc_handler(uint32_t smc_fid, u_register_t x1,
				    u_register_t x2, u_register_t x3,
				    u_register_t x4, void *cookie, void *handle,
				    u_register_t flags)
{
	cpu_context_t *ns_cpu_context;
	uint32_t linear_id = plat_my_core_pos();
	optee_context_t *optee_ctx = &opteed_sp_context[linear_id];

	/*
	 * 确定此 SMC 来自哪个安全状态
	 */

	if (is_caller_non_secure(flags)) {
#if OPTEE_ALLOW_SMC_LOAD
		if (opteed_allow_load && smc_fid == NSSMC_OPTEED_CALL_UID) {
			/* 提供镜像加载服务的 UUID。 */
			SMC_UUID_RET(handle, optee_image_load_uuid);
		}
		if (smc_fid == NSSMC_OPTEED_CALL_LOAD_IMAGE) {
			/*
			 * TODO: 考虑在调用后从内存中擦除 SMC 加载代码，
			 * 类似于在 RECLAIM_INIT 下所做的，但扩展到稍后发生。
			 */
			if (!opteed_allow_load) {
				SMC_RET1(handle, -EPERM);
			}

			opteed_allow_load = false;
			uint64_t data_size = dual32to64(x1, x2);
			uint64_t data_pa = dual32to64(x3, x4);
			if (!data_size || !data_pa) {
				/*
				 * 当 OP-TEE 镜像在内核中未正确加载但我们想要
				 * 出于安全原因阻止以后加载它时调用此函数。
				 */
				SMC_RET1(handle, -EINVAL);
			}
			SMC_RET1(handle,
				 opteed_handle_smc_load(data_size, data_pa));
		}
#endif /* OPTEE_ALLOW_SMC_LOAD */
		/*
		 * 这是非安全客户端的新请求。
		 * 参数在 x1 和 x2 中。确定需要保留哪些寄存器，
		 * 保存非安全状态并将请求发送到安全负载。
		 */
		assert(handle == cm_get_context(NON_SECURE));

		cm_el1_sysregs_context_save(NON_SECURE);

		/*
		 * 我们已完成存储非安全上下文。现在要求 OP-TEE 执行工作。
		 * 如果我们通过 SMC 加载，则还需要初始化此 CPU 上下文（如果尚未完成）。
		 */
		if (optee_vector_table == NULL) {
			SMC_RET1(handle, -EINVAL);
		}

		if (get_optee_pstate(optee_ctx->state) ==
		    OPTEE_PSTATE_UNKNOWN) {
			opteed_cpu_on_finish_handler(0);
		}

		/*
		 * 验证是否存在有效的上下文，将操作类型和参数复制到安全上下文，
		 * 并跳转到安全负载中的快速 smc 入口点。从此函数退出时将进入 S-EL1。
		 */
		assert(&optee_ctx->cpu_ctx == cm_get_context(SECURE));

		/* 为 SMC 设置适当的入口。
		 * 我们期望 OPTEE 适当地管理 PSTATE.I 和 PSTATE.F 标志。
		 */
		if (GET_SMC_TYPE(smc_fid) == SMC_TYPE_FAST) {
			cm_set_elr_el3(
				SECURE,
				(uint64_t)&optee_vector_table->fast_smc_entry);
		} else {
			cm_set_elr_el3(
				SECURE,
				(uint64_t)&optee_vector_table->yield_smc_entry);
		}

		cm_el1_sysregs_context_restore(SECURE);
		cm_set_next_eret_context(SECURE);

		write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx), CTX_GPREG_X4,
			      read_ctx_reg(get_gpregs_ctx(handle),
					   CTX_GPREG_X4));
		write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx), CTX_GPREG_X5,
			      read_ctx_reg(get_gpregs_ctx(handle),
					   CTX_GPREG_X5));
		write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx), CTX_GPREG_X6,
			      read_ctx_reg(get_gpregs_ctx(handle),
					   CTX_GPREG_X6));
		/* 传播虚拟机监控程序客户端 ID */
		write_ctx_reg(get_gpregs_ctx(&optee_ctx->cpu_ctx), CTX_GPREG_X7,
			      read_ctx_reg(get_gpregs_ctx(handle),
					   CTX_GPREG_X7));

		SMC_RET4(&optee_ctx->cpu_ctx, smc_fid, x1, x2, x3);
	}

	/*
	 * 从 OPTEE 返回
	 */

	switch (smc_fid) {
	/*
	 * OPTEE 在冷启动后完成了自身的初始化
	 */
	case TEESMC_OPTEED_RETURN_ENTRY_DONE:
		/*
		 * 存储 OPTEE 入口点信息。这仅在主 CPU 上执行一次
		 */
		assert(optee_vector_table == NULL);
		optee_vector_table = (optee_vectors_t *)x1;

		if (optee_vector_table != NULL) {
			set_optee_pstate(optee_ctx->state, OPTEE_PSTATE_ON);

			/*
			 * OPTEE 已成功初始化。
			 * 向 PSCI 注册电源管理钩子
			 */
			psci_register_spd_pm_hook(&opteed_pm);

#if !OPTEE_ALLOW_SMC_LOAD
			register_opteed_interrupt_handler();
#endif
		}

		/*
		 * OPTEE 报告完成。OPTEED 必须已通过同步进入 OPTEE 发起原始请求。
		 * 跳回到原始的 C 运行时上下文。
		 */
		opteed_synchronous_sp_exit(optee_ctx, x1);
		break;

	/*
	 * 这些函数 ID 仅由 OP-TEE 使用，以表明它已完成：
	 * 1. 响应早期 psci cpu_on 请求开启自身
	 * 2. 在早期 psci cpu_suspend 请求后恢复自身
	 */
	case TEESMC_OPTEED_RETURN_ON_DONE:
	case TEESMC_OPTEED_RETURN_RESUME_DONE:

	/*
	 * 这些函数 ID 仅由 SP 使用，以表明它已完成：
	 * 1. 在早期 psci cpu_suspend 请求后暂停自身
	 * 2. 响应早期 psci cpu_off 请求关闭自身
	 */
	case TEESMC_OPTEED_RETURN_OFF_DONE:
	case TEESMC_OPTEED_RETURN_SUSPEND_DONE:
	case TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE:
	case TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE:

		/*
		 * OPTEE 报告完成。OPTEED 必须已通过同步进入 OPTEE 发起原始请求。
		 * 跳回到原始的 C 运行时上下文，并将 x1 作为返回值传递给调用者
		 */
		opteed_synchronous_sp_exit(optee_ctx, x1);
		break;

	/*
	 * OPTEE 正在从调用返回或从中断调用，无论哪种情况都应在正常世界中恢复执行。
	 */
	case TEESMC_OPTEED_RETURN_CALL_DONE:
		/*
		 * 这是来自早期请求的安全客户端的结果。结果在 x0-x3 中。
		 * 将其复制到非安全上下文，保存安全状态并返回到非安全状态。
		 */
		assert(handle == cm_get_context(SECURE));
		cm_el1_sysregs_context_save(SECURE);

		/* 获取对非安全上下文的引用 */
		ns_cpu_context = cm_get_context(NON_SECURE);
		assert(ns_cpu_context);

		/* 恢复非安全状态 */
		cm_el1_sysregs_context_restore(NON_SECURE);
		cm_set_next_eret_context(NON_SECURE);

		SMC_RET4(ns_cpu_context, x1, x2, x3, x4);

	/*
	 * OPTEE 已完成处理 S-EL1 FIQ 中断。应在正常世界中恢复执行。
	 */
	case TEESMC_OPTEED_RETURN_FIQ_DONE:
		/* 获取对非安全上下文的引用 */
		ns_cpu_context = cm_get_context(NON_SECURE);
		assert(ns_cpu_context);

		/*
		 * 恢复非安全状态。由于 OPTEE 在处理 S-EL1 中断期间应该保留它，
		 * 因此无需保存安全系统寄存器上下文。
		 */
		cm_el1_sysregs_context_restore(NON_SECURE);
		cm_set_next_eret_context(NON_SECURE);

		SMC_RET0((uint64_t)ns_cpu_context);

	default:
		panic();
	}
}

/* 为快速 SMC 调用定义 OPTEED 运行时服务描述符 */
DECLARE_RT_SVC(opteed_fast,

	       OEN_TOS_START, OEN_TOS_END, SMC_TYPE_FAST, opteed_setup,
	       opteed_smc_handler);

/* 为可中断 SMC 调用定义 OPTEED 运行时服务描述符 */
DECLARE_RT_SVC(opteed_std,

	       OEN_TOS_START, OEN_TOS_END, SMC_TYPE_YIELD, NULL,
	       opteed_smc_handler);