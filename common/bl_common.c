/*
 * Copyright (c) 2013-2024, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2025, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <common/bl_common.h>
#include <common/build_message.h>
#include <common/debug.h>
#include <drivers/auth/auth_mod.h>
#include <drivers/io/io_storage.h>
#include <lib/utils.h>
#include <lib/xlat_tables/xlat_tables_defs.h>
#include <plat/common/platform.h>

#if TRUSTED_BOARD_BOOT
# ifdef DYN_DISABLE_AUTH
static int disable_auth;

/******************************************************************************
 * 动态禁用认证的API接口。仅适用于开发系统。
 * 仅在定义了DYN_DISABLE_AUTH时才会调用此函数。
 *****************************************************************************/
void dyn_disable_auth(void)
{
	INFO("动态禁用镜像认证\n");
	disable_auth = 1;
}
# endif /* DYN_DISABLE_AUTH */

/******************************************************************************
 * 判断认证是否被动态禁用的函数
 *****************************************************************************/
static int dyn_is_auth_disabled(void)
{
# ifdef DYN_DISABLE_AUTH
	return disable_auth;
# else
	return 0;
# endif
}
#endif /* TRUSTED_BOARD_BOOT */

/*
 * 页面对齐函数
 * 参数:
 *   value: 需要对齐的值
 *   dir: 对齐方向(UP向上对齐, DOWN向下对齐)
 * 返回: 对齐后的值
 */
uintptr_t page_align(uintptr_t value, unsigned dir)
{
	/* 向上舍入到下一页边界 */
	if ((value & PAGE_SIZE_MASK) != 0U) {
		value &= ~PAGE_SIZE_MASK;
		if (dir == UP) {
			value += PAGE_SIZE;
		}
	}

	return value;
}

/*******************************************************************************
 * 内部函数，用于在指定地址加载镜像
 * 给定镜像ID和可用内存范围
 *
 * 如果加载成功，则更新镜像信息
 *
 * 成功返回0，失败返回负错误码
 ******************************************************************************/
static int load_image(unsigned int image_id, image_info_t *image_data)
{
	uintptr_t dev_handle = 0ULL;
	uintptr_t image_handle = 0ULL;
	uintptr_t image_spec = 0ULL;
	uintptr_t image_base;
	size_t image_size = 0ULL;
	size_t bytes_read = 0ULL;
	int io_result;

	assert(image_data != NULL);
	assert(image_data->h.version >= VERSION_2);

	image_base = image_data->image_base;

	/* 通过查询平台层获取镜像引用 */
	io_result = plat_get_image_source(image_id, &dev_handle, &image_spec);
	if (io_result != 0) {
		WARN("无法获取镜像引用 id=%u (%i)\n",
			image_id, io_result);
		return io_result;
	}

	/* 尝试访问镜像 */
	io_result = io_open(dev_handle, image_spec, &image_handle);
	if (io_result != 0) {
		WARN("无法访问镜像 id=%u (%i)\n",
			image_id, io_result);
		return io_result;
	}

	INFO("正在加载镜像 id=%u 到地址 0x%lx\n", image_id, image_base);

	/* 查找镜像大小 */
	io_result = io_size(image_handle, &image_size);
	if (io_result != 0) {
		WARN("无法确定镜像大小 id=%u (%i)\n",
			image_id, io_result);
		goto exit_load_image;
	}

	if (image_size == 0U) {
		WARN("镜像 id=%u 大小为零\n", image_id);
		io_result = -EIO;
		goto exit_load_image;
	}

	/* 检查要加载的镜像大小是否在限制范围内 */
	if (image_size > image_data->image_max_size) {
		WARN("镜像 id=%u 大小超出界限\n", image_id);
		io_result = -EFBIG;
		goto exit_load_image;
	}

	/*
	 * image_data->image_max_size 是uint32_t类型，所以image_size总是
	 * 能适应image_data->image_size
	 */
	image_data->image_size = (uint32_t)image_size;

	/* 有足够的空间，现在加载镜像 */
	/* TODO: 考虑是否尝试恢复/重试部分成功的读取 */
	io_result = io_read(image_handle, image_base, image_size, &bytes_read);
	if ((io_result != 0) || (bytes_read < image_size)) {
		WARN("无法加载镜像 id=%u (%i)\n", image_id, io_result);
		goto exit_load_image;
	}

	INFO("镜像 id=%u 已加载: 0x%lx - 0x%lx\n", image_id, image_base,
	     (uintptr_t)(image_base + image_size));

exit_load_image:
	(void)io_close(image_handle);
	/* 忽略'close'中不太可能/无法恢复的错误 */

	/* TODO: 考虑在此引导加载程序阶段保持设备连接打开 */
	(void)io_dev_close(dev_handle);
	/* 忽略'dev_close'中不太可能/无法恢复的错误 */

	return io_result;
}

#if TRUSTED_BOARD_BOOT
/*
 * 此函数使用递归来认证父镜像直到信任根
 */
static int load_auth_image_recursive(unsigned int image_id,
				    image_info_t *image_data)
{
	int rc;
	unsigned int parent_id;

	/* 使用递归认证父镜像 */
	rc = auth_mod_get_parent_id(image_id, &parent_id);
	if (rc == 0) {
		rc = load_auth_image_recursive(parent_id, image_data);
		if (rc != 0) {
			return rc;
		}
	}

	/* 加载镜像 */
	rc = load_image(image_id, image_data);
	if (rc != 0) {
		return rc;
	}

	/* 认证镜像 */
	rc = auth_mod_verify_img(image_id,
				 (void *)image_data->image_base,
				 image_data->image_size);
	if (rc != 0) {
		/* 认证错误，清零内存并立即刷新 */
		zero_normalmem((void *)image_data->image_base,
			       image_data->image_size);
		flush_dcache_range(image_data->image_base,
				   image_data->image_size);
		return -EAUTH;
	}

	return 0;
}
#endif /* TRUSTED_BOARD_BOOT */

/*
 * 内部加载认证镜像函数
 */
static int load_auth_image_internal(unsigned int image_id,
				    image_info_t *image_data)
{
#if TRUSTED_BOARD_BOOT
	if (dyn_is_auth_disabled() == 0) {
		return load_auth_image_recursive(image_id, image_data);
	}
#endif

	return load_image(image_id, image_data);
}

/*******************************************************************************
 * 通用函数用于加载和认证镜像。实际通过调用'load_image()'函数加载镜像。
 * 因此，如果加载操作失败，它返回相同的错误码，或者如果认证失败则返回-EAUTH。
 * 此外，该函数使用递归认证父镜像直到信任根（如果启用了TBB）。
 ******************************************************************************/
int load_auth_image(unsigned int image_id, image_info_t *image_data)
{
	int err;

	/* 检查平台镜像操作函数是否存在 */
	if ((plat_try_img_ops == NULL) || (plat_try_img_ops->next_instance == NULL)) {
		err = load_auth_image_internal(image_id, image_data);
	} else {
		/* 循环尝试不同实例直到成功 */
		do {
			err = load_auth_image_internal(image_id, image_data);
			if (err != 0) {
				/* 如果当前实例失败，尝试下一个实例 */
				if (plat_try_img_ops->next_instance(image_id) != 0) {
					return err;
				}
			}
		} while (err != 0);
	}

	/* 如果加载成功（在可信启动流程中还包括认证） */
	if (err == 0) {
		/*
		 * 如果镜像加载成功（以及在可信启动流程中的认证），
		 * 则对其进行测量（如果启用了MEASURED_BOOT标志）
		 */
		err = plat_mboot_measure_image(image_id, image_data);
		if (err != 0) {
			return err;
		}

		/*
		 * 将镜像刷新到主内存，以便后续任何CPU都可以执行它，
		 * 无论缓存和MMU状态如何
		 */
		flush_dcache_range(image_data->image_base,
				   image_data->image_size);
	}

	return err;
}

/*******************************************************************************
 * 打印entry_point_info_t结构体的内容
 ******************************************************************************/
void print_entry_point_info(const entry_point_info_t *ep_info)
{
	INFO("入口点地址 = 0x%lx\n", ep_info->pc);
	INFO("SPSR = 0x%x\n", ep_info->spsr);

#define PRINT_IMAGE_ARG(n)					\
	VERBOSE("参数 #" #n " = 0x%llx\n",			\
		(unsigned long long) ep_info->args.arg##n)

	PRINT_IMAGE_ARG(0);
	PRINT_IMAGE_ARG(1);
	PRINT_IMAGE_ARG(2);
	PRINT_IMAGE_ARG(3);
#ifdef __aarch64__
	PRINT_IMAGE_ARG(4);
	PRINT_IMAGE_ARG(5);
	PRINT_IMAGE_ARG(6);
	PRINT_IMAGE_ARG(7);
#endif
#undef PRINT_IMAGE_ARG
}

/*
 * 此函数用于返回TF-A版本
 */
const char *get_version(void)
{
	return build_version;
}