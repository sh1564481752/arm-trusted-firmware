/*
 * Copyright (c) 2016-2022, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdint.h>

#include <plat/common/platform.h>
#include <platform_def.h>

#include <arch.h>
#include <arch_helpers.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/desc_image_load.h>
#include <drivers/auth/auth_mod.h>

#include "bl2_private.h"

/*******************************************************************************
 * 函数功能：加载SCP_BL2/BL3x镜像，并返回下一个可执行镜像的入口点信息。
 *
 * 参数说明：
 *   无显式参数。
 *
 * 返回值说明：
 *   返回指向下一个可执行镜像入口点信息的指针（entry_point_info结构体）。
 ******************************************************************************/
struct entry_point_info *bl2_load_images(void)
{
	bl_params_t *bl2_to_next_bl_params;
	bl_load_info_t *bl2_load_info;
	const bl_load_info_node_t *bl2_node_info;
	int plat_setup_done = 0;
	int err;

	/*
	 * 获取需要加载的镜像信息。
	 */
	bl2_load_info = plat_get_bl_image_load_info();
	assert(bl2_load_info != NULL);
	assert(bl2_load_info->head != NULL);
	assert(bl2_load_info->h.type == PARAM_BL_LOAD_INFO);
	assert(bl2_load_info->h.version >= VERSION_2);
	bl2_node_info = bl2_load_info->head;

	while (bl2_node_info != NULL) {
		/*
		 * 如果镜像属性中指示需要进行平台设置，并且尚未完成平台设置，
		 * 则执行平台设置操作。
		 */
		if ((bl2_node_info->image_info->h.attr &
		     IMAGE_ATTRIB_PLAT_SETUP) != 0U) {
			if (plat_setup_done != 0) {
				WARN("BL2: Platform setup already done!!\n");
			} else {
				INFO("BL2: Doing platform setup\n");
				bl2_platform_setup();
				plat_setup_done = 1;
			}
		}

		/*
		 * 在加载镜像之前，调用平台特定的预处理函数。
		 */
		err = bl2_plat_handle_pre_image_load(bl2_node_info->image_id);
		if (err != 0) {
			ERROR("BL2: Failure in pre image load handling (%i)\n",
			      err);
			plat_error_handler(err);
		}

		/*
		 * 根据镜像属性决定是否跳过加载。如果不跳过，则加载并验证镜像。
		 */
		if ((bl2_node_info->image_info->h.attr &
		     IMAGE_ATTRIB_SKIP_LOADING) == 0U) {
			INFO("BL2: Loading image id %u\n",
			     bl2_node_info->image_id);
			err = load_auth_image(bl2_node_info->image_id,
					      bl2_node_info->image_info);
			if (err != 0) {
				ERROR("BL2: Failed to load image id %u (%i)\n",
				      bl2_node_info->image_id, err);
				plat_error_handler(err);
			}
		} else {
			INFO("BL2: Skip loading image id %u\n",
			     bl2_node_info->image_id);
		}

		/*
		 * 加载完成后，调用平台特定的后处理函数。
		 */
		err = bl2_plat_handle_post_image_load(bl2_node_info->image_id);
		if (err != 0) {
			ERROR("BL2: Failure in post image load handling (%i)\n",
			      err);
			plat_error_handler(err);
		}

		/* 移动到下一个镜像节点 */
		bl2_node_info = bl2_node_info->next_load_info;
	}

	/*
	 * 获取传递给下一个镜像的信息。
	 */
	bl2_to_next_bl_params = plat_get_next_bl_params();
	assert(bl2_to_next_bl_params != NULL);
	assert(bl2_to_next_bl_params->head != NULL);
	assert(bl2_to_next_bl_params->h.type == PARAM_BL_PARAMS);
	assert(bl2_to_next_bl_params->h.version >= VERSION_2);
	assert(bl2_to_next_bl_params->head->ep_info != NULL);

	/*
	 * 如果未提供arg0参数，则填充为指向bl2_to_next_bl_params的指针。
	 */
	if (bl2_to_next_bl_params->head->ep_info->args.arg0 == (u_register_t)0)
		bl2_to_next_bl_params->head->ep_info->args.arg0 =
			(u_register_t)bl2_to_next_bl_params;

	/*
	 * 将传递给下一个镜像的参数刷新到内存中。
	 */
	plat_flush_next_bl_params();

	/*
	 * 返回下一个镜像的入口点信息。
	 */
	return bl2_to_next_bl_params->head->ep_info;
}