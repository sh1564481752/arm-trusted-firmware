/*
 * Copyright (c) 2017-2025, Arm Limited and Contributors. All rights reserved.
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
 * 定义内存区域。根据是否启用 BL2_IN_XIP_MEM 和 SEPARATE_BL2_NOLOAD_REGION，
 * 分别配置 ROM、RAM 和 RAM_NOLOAD 区域的起始地址和长度。
 */
MEMORY {
#if BL2_IN_XIP_MEM
    ROM (rx): ORIGIN = BL2_RO_BASE, LENGTH = BL2_RO_LIMIT - BL2_RO_BASE
    RAM (rwx): ORIGIN = BL2_RW_BASE, LENGTH = BL2_RW_LIMIT - BL2_RW_BASE
#else /* BL2_IN_XIP_MEM */
    RAM (rwx): ORIGIN = BL2_BASE, LENGTH = BL2_LIMIT - BL2_BASE
#endif /* BL2_IN_XIP_MEM */

#if SEPARATE_BL2_NOLOAD_REGION
    RAM_NOLOAD (rw!a): ORIGIN = BL2_NOLOAD_START, LENGTH = BL2_NOLOAD_LIMIT - BL2_NOLOAD_START
#else /* SEPARATE_BL2_NOLOAD_REGION */
#   define RAM_NOLOAD RAM
#endif /* SEPARATE_BL2_NOLOAD_REGION */
}

/*
 * 如果未启用 BL2_IN_XIP_MEM，则将 ROM 定义为 RAM。
 */
#if !BL2_IN_XIP_MEM
#   define ROM RAM
#endif /* !BL2_IN_XIP_MEM */

/*
 * 定义链接器脚本的各个段（SECTIONS），包括代码段、只读数据段、可读写数据段等。
 * 根据是否启用 BL2_IN_XIP_MEM 和 SEPARATE_CODE_AND_RODATA，分别处理不同的内存布局。
 */
SECTIONS {
    RAM_REGION_START = ORIGIN(RAM);
    RAM_REGION_LENGTH = LENGTH(RAM);
#if BL2_IN_XIP_MEM
    ROM_REGION_START = ORIGIN(ROM);
    ROM_REGION_LENGTH = LENGTH(ROM);

    . = BL2_RO_BASE;

    /*
     * 检查 BL2_RO_BASE 是否按页对齐。
     */
    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL2_RO_BASE address is not aligned on a page boundary.")
#else /* BL2_IN_XIP_MEM */
    . = BL2_BASE;

    /*
     * 检查 BL2_BASE 是否按页对齐。
     */
    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL2_BASE address is not aligned on a page boundary.")
#endif /* BL2_IN_XIP_MEM */

#if SEPARATE_BL2_NOLOAD_REGION
    RAM_NOLOAD_REGION_START = ORIGIN(RAM_NOLOAD);
    RAM_NOLOAD_REGION_LENGTH = LENGTH(RAM_NOLOAD);
#endif

#if SEPARATE_CODE_AND_RODATA

/*
 * 如果平台未定义 BL2_TEXT_RESIDENT_LIMIT，则默认设置为 4K。
 */
#ifndef BL2_TEXT_RESIDENT_LIMIT
#define BL2_TEXT_RESIDENT_LIMIT		U(0x1000)
#endif

    /*
     * 定义 .text 段，包含启动代码和其他文本段内容。
     * 确保 resident 部分不超过 BL2_TEXT_RESIDENT_LIMIT 的限制。
     */
    .text . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".text address is not aligned on a page boundary.");

        __TEXT_START__ = .;
        __TEXT_RESIDENT_START__ = .;

        *bl2_el3_entrypoint.o(.text*)
        *(.text.asm.*)

        __TEXT_RESIDENT_END__ = .;

        *(SORT_BY_ALIGNMENT(.text*))
        *(.vectors)
        __TEXT_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __TEXT_END__ = .;
    } >ROM

    /*
     * 定义 .rodata 段，包含只读数据。
     */
    .rodata . : {
        __RODATA_START__ = .;

        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        __RODATA_END_UNALIGNED__ = .;
        . = ALIGN(PAGE_SIZE);

        __RODATA_END__ = .;
    } >ROM

    /*
     * 检查 resident 部分是否超出限制。
     */
    ASSERT(__TEXT_RESIDENT_END__ - __TEXT_RESIDENT_START__ <=
	BL2_TEXT_RESIDENT_LIMIT,
        "Resident part of BL2 has exceeded its limit.")
#else /* SEPARATE_CODE_AND_RODATA */
    /*
     * 合并 .text 和 .rodata 到一个段中。
     */
    .ro . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".ro address is not aligned on a page boundary.");

        __RO_START__ = .;
        __TEXT_RESIDENT_START__ = .;

        *bl2_el3_entrypoint.o(.text*)
        *(.text.asm.*)

        __TEXT_RESIDENT_END__ = .;

        *(SORT_BY_ALIGNMENT(.text*))
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        *(.vectors)

        __RO_END_UNALIGNED__ = .;

        /*
         * 确保当前页的剩余空间未被使用，以避免 RW 数据混入。
         */
        . = ALIGN(PAGE_SIZE);

        __RO_END__ = .;
    } >ROM
#endif /* SEPARATE_CODE_AND_RODATA */

/*
 * 如果启用了 RESET_TO_BL2，则检查 cpu_ops 是否已定义。
 */
#if RESET_TO_BL2
    ASSERT(__CPU_OPS_END__ > __CPU_OPS_START__,
        "cpu_ops not defined for this platform.")
#endif

#if BL2_IN_XIP_MEM
    ROM_REGION_END = .;
    . = BL2_RW_BASE;

    /*
     * 检查 BL2_RW_BASE 是否按页对齐。
     */
    ASSERT(BL2_RW_BASE == ALIGN(PAGE_SIZE),
           "BL2_RW_BASE address is not aligned on a page boundary.")
#endif /* BL2_IN_XIP_MEM */

    __RW_START__ = .;

    /*
     * 定义数据段，加载到 RAM 中但存储在 ROM 中。
     */
    DATA_SECTION >RAM AT>ROM

    __DATA_RAM_START__ = __DATA_START__;
    __DATA_RAM_END__ = __DATA_END__;

    /*
     * 定义重定位段。
     */
    RELA_SECTION >RAM

#if SEPARATE_BL2_NOLOAD_REGION
    SAVED_ADDR = .;

    . = BL2_NOLOAD_START;

    __BL2_NOLOAD_START__ = .;
#endif /* SEPARATE_BL2_NOLOAD_REGION */

    /*
     * 定义栈段、BSS 段和页表段。
     */
    STACK_SECTION >RAM_NOLOAD
    BSS_SECTION >RAM_NOLOAD
    XLAT_TABLE_SECTION >RAM_NOLOAD

#if SEPARATE_BL2_NOLOAD_REGION
    __BL2_NOLOAD_END__ = .;
    RAM_NOLOAD_REGION_END = .;

    . = SAVED_ADDR;
#endif /* SEPARATE_BL2_NOLOAD_REGION */

#if USE_COHERENT_MEM
    /*
     * 定义 coherent 内存段，确保其按页对齐。
     */
    .coherent_ram (NOLOAD) : ALIGN(PAGE_SIZE) {
        __COHERENT_RAM_START__ = .;

        *(.tzfw_coherent_mem)

        __COHERENT_RAM_END_UNALIGNED__ = .;

        /*
         * 确保当前页的剩余空间未被使用。
         */
        . = ALIGN(PAGE_SIZE);

        __COHERENT_RAM_END__ = .;
    } >RAM
#endif /* USE_COHERENT_MEM */

    __RW_END__ = .;
    __BL2_END__ = .;

    /*
     * 丢弃动态符号表等相关段。
     */
    /DISCARD/ : {
        *(.dynsym .dynstr .hash .gnu.hash)
    }

#if BL2_IN_XIP_MEM
    __BL2_RAM_START__ = ADDR(.data);
    __BL2_RAM_END__ = .;

    __DATA_ROM_START__ = LOADADDR(.data);
    __DATA_SIZE__ = SIZEOF(.data);

    /*
     * 计算 BL2 在 XIP 内存中的 RO 内容结束地址。
     */
    __BL2_ROM_END__ =  __DATA_ROM_START__ + __DATA_SIZE__;

    /*
     * 检查 BL2 的 RO 内容是否超出限制。
     */
    ASSERT(__BL2_ROM_END__ <= BL2_RO_LIMIT,
           "BL2's RO content has exceeded its limit.")
#endif /* BL2_IN_XIP_MEM */

    __BSS_SIZE__ = SIZEOF(.bss);

#if USE_COHERENT_MEM
    __COHERENT_RAM_UNALIGNED_SIZE__ =
        __COHERENT_RAM_END_UNALIGNED__ - __COHERENT_RAM_START__;
#endif /* USE_COHERENT_MEM */

    RAM_REGION_END = .;
#if BL2_IN_XIP_MEM
    /*
     * 检查 BL2 的 RW 内容是否超出限制。
     */
    ASSERT(. <= BL2_RW_LIMIT, "BL2's RW content has exceeded its limit.")
#else /* BL2_IN_XIP_MEM */
    /*
     * 检查 BL2 镜像是否超出限制。
     */
    ASSERT(. <= BL2_LIMIT, "BL2 image has exceeded its limit.")
#endif /* BL2_IN_XIP_MEM */
}