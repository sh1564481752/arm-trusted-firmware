/*
 * Copyright (c) 2013-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/bl_common.ld.h>
#include <lib/xlat_tables/xlat_tables_defs.h>

/* 
 * 设置输出格式和架构，并指定入口点为 bl2_entrypoint。
 */
OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)
ENTRY(bl2_entrypoint)

/*
 * 定义内存区域 RAM，起始地址为 BL2_BASE，长度为 BL2_LIMIT - BL2_BASE。
 */
MEMORY {
    RAM (rwx): ORIGIN = BL2_BASE, LENGTH = BL2_LIMIT - BL2_BASE
}

SECTIONS {
    /*
     * 初始化 RAM 区域的起始地址和长度。
     */
    RAM_REGION_START = ORIGIN(RAM);
    RAM_REGION_LENGTH = LENGTH(RAM);
    . = BL2_BASE;

    /*
     * 断言检查：确保 BL2_BASE 地址按页面边界对齐。
     */
    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL2_BASE address is not aligned on a page boundary.")

#if SEPARATE_CODE_AND_RODATA
    /*
     * 定义 .text 段，包含可执行代码。
     * 确保该段按页面边界对齐，并记录起始和结束地址。
     */
    .text . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".text address is not aligned on a page boundary.");

        __TEXT_START__ = .;

        *bl2_entrypoint.o(.text*)

        *(SORT_BY_ALIGNMENT(.text*))
        *(.vectors)
        __TEXT_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __TEXT_END__ = .;
    } >RAM

    /*
     * 添加 .ARM.extab 和 .ARM.exidx 段，供 Clang 编译器使用。
     */
    .ARM.extab . : {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } >RAM

    .ARM.exidx . : {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } >RAM

    /*
     * 定义 .rodata 段，包含只读数据。
     * 记录起始和结束地址，并确保按页面边界对齐。
     */
    .rodata . : {
        __RODATA_START__ = .;

        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        __RODATA_END_UNALIGNED__ = .;
        . = ALIGN(PAGE_SIZE);

        __RODATA_END__ = .;
    } >RAM
#else /* SEPARATE_CODE_AND_RODATA */
    /*
     * 当未分离代码和只读数据时，定义 .ro 段。
     * 包含代码、只读数据和向量表，并确保按页面边界对齐。
     */
    .ro . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".ro address is not aligned on a page boundary.");

        __RO_START__ = .;

        *bl2_entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        *(.vectors)

        __RO_END_UNALIGNED__ = .;

        /*
         * 确保当前内存页的剩余部分未被使用，
         * 以保证映射到此段的内存页具有正确的只读和可执行属性。
         */
        . = ALIGN(PAGE_SIZE);

        __RO_END__ = .;
    } >RAM
#endif /* SEPARATE_CODE_AND_RODATA */

    /*
     * 定义读写数据段的起始地址。
     */
    __RW_START__ = .;

    /*
     * 定义数据段、栈段、BSS 段和页表段。
     */
    DATA_SECTION >RAM
    STACK_SECTION >RAM
    BSS_SECTION >RAM
    XLAT_TABLE_SECTION >RAM

#if USE_COHERENT_MEM
    /*
     * 定义一致性内存段（coherent memory）。
     * 起始地址必须按页面边界对齐，以确保一致性数据独立存储在自己的页面中。
     */
    .coherent_ram (NOLOAD) : ALIGN(PAGE_SIZE) {
        __COHERENT_RAM_START__ = .;
        *(.tzfw_coherent_mem)
        __COHERENT_RAM_END_UNALIGNED__ = .;

        /*
         * 确保当前内存页的剩余部分未被使用，
         * 以保证映射到此段的内存页具有正确的设备内存属性。
         */
        . = ALIGN(PAGE_SIZE);

        __COHERENT_RAM_END__ = .;
    } >RAM
#endif /* USE_COHERENT_MEM */

    /*
     * 定义读写数据段和 BL2 镜像的结束地址。
     */
    __RW_END__ = .;
    __BL2_END__ = .;
    RAM_REGION_END = .;

    /*
     * 计算 BSS 段的大小。
     */
    __BSS_SIZE__ = SIZEOF(.bss);

#if USE_COHERENT_MEM
    /*
     * 计算一致性内存段的实际大小（未对齐部分）。
     */
    __COHERENT_RAM_UNALIGNED_SIZE__ =
        __COHERENT_RAM_END_UNALIGNED__ - __COHERENT_RAM_START__;
#endif /* USE_COHERENT_MEM */

    /*
     * 断言检查：确保 BL2 镜像未超出其限制范围。
     */
    ASSERT(. <= BL2_LIMIT, "BL2 image has exceeded its limit.")
}