/*
 * Copyright (c) 2013-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * 链接脚本文件，用于定义BL1（Boot Loader Stage 1）的内存布局和段分配。
 * 该脚本指定代码、只读数据、可读写数据等在ROM和RAM中的位置，
 * 并确保各段满足对齐要求以优化性能和内存管理。
 */

/*
 * 定义.data段的对齐要求为16字节，以便在运行时高效复制16字节对齐的数据区域。
 */
#define DATA_ALIGN	16

#include <common/bl_common.ld.h>
#include <lib/xlat_tables/xlat_tables_defs.h>

/*
 * 指定输出格式和架构类型，ENTRY定义程序入口点为bl1_entrypoint。
 */
OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)
ENTRY(bl1_entrypoint)

/*
 * 定义内存区域：ROM用于存储只读代码和数据，RAM用于存储可读写数据。
 * ROM区域从BL1_RO_BASE开始，长度为BL1_RO_LIMIT - BL1_RO_BASE；
 * RAM区域从BL1_RW_BASE开始，长度为BL1_RW_LIMIT - BL1_RW_BASE。
 */
MEMORY {
    ROM (rx): ORIGIN = BL1_RO_BASE, LENGTH = BL1_RO_LIMIT - BL1_RO_BASE
    RAM (rwx): ORIGIN = BL1_RW_BASE, LENGTH = BL1_RW_LIMIT - BL1_RW_BASE
}

SECTIONS {
    /*
     * 记录ROM和RAM区域的起始地址及长度，供后续使用。
     */
    ROM_REGION_START = ORIGIN(ROM);
    ROM_REGION_LENGTH = LENGTH(ROM);
    RAM_REGION_START = ORIGIN(RAM);
    RAM_REGION_LENGTH = LENGTH(RAM);

    /*
     * 设置当前位置为BL1_RO_BASE，并断言其按页对齐。
     */
    . = BL1_RO_BASE;

    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL1_RO_BASE address is not aligned on a page boundary.")

#if SEPARATE_CODE_AND_RODATA
    /*
     * 当启用代码与只读数据分离时，定义.text段：
     * 包含入口点代码、排序后的文本段以及向量表。
     * 确保.text段按页对齐。
     */
    .text . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".text address is not aligned on a page boundary.");

        __TEXT_START__ = .;

        *bl1_entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(.vectors)
        __TEXT_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __TEXT_END__ = .;
    } >ROM

    /*
     * 添加.ARM.extab和.ARM.exidx段，供Clang编译器使用。
     */
    .ARM.extab . : {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } >ROM

    .ARM.exidx . : {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } >ROM

    /*
     * 定义.rodata段，包含只读数据。
     * 不需要填充到页边界，但需填充到16字节边界以满足.data段对齐需求。
     */
    .rodata . : {
        __RODATA_START__ = .;

        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        __RODATA_END_UNALIGNED__ = .;
        __RODATA_END__ = .;

        . = ALIGN(16);
    } >ROM
#else /* SEPARATE_CODE_AND_RODATA */
    /*
     * 当未启用代码与只读数据分离时，将所有只读内容合并到.ro段中。
     * 同样确保.ro段按页对齐，并填充到16字节边界。
     */
    .ro . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".ro address is not aligned on a page boundary.");

        __RO_START__ = .;

        *bl1_entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        *(.vectors)

        __RO_END__ = .;

        . = ALIGN(16);
    } >ROM
#endif /* SEPARATE_CODE_AND_RODATA */

    /*
     * 断言cpu_ops已正确定义。
     */
    ASSERT(__CPU_OPS_END__ > __CPU_OPS_START__,
        "cpu_ops not defined for this platform.")

    /*
     * 标记ROM区域结束，并设置当前位置为BL1_RW_BASE。
     */
    ROM_REGION_END = .;
    . = BL1_RW_BASE;

    /*
     * 断言BL1_RW_BASE按页对齐。
     */
    ASSERT(BL1_RW_BASE == ALIGN(PAGE_SIZE),
        "BL1_RW_BASE address is not aligned on a page boundary.")

    /*
     * 定义RW段的起始地址。
     */
    __RW_START__ = .;

    /*
     * 定义.data段，加载到RAM中但存储在ROM中。
     */
    DATA_SECTION >RAM AT>ROM

    __DATA_RAM_START__ = __DATA_START__;
    __DATA_RAM_END__ = __DATA_END__;

    /*
     * 定义栈、BSS和页表段。
     */
    STACK_SECTION >RAM
    BSS_SECTION >RAM
    XLAT_TABLE_SECTION >RAM

#if USE_COHERENT_MEM
    /*
     * 如果启用了相干内存，则定义.coherent_ram段。
     * 确保其基地址按页对齐，并标记为设备内存。
     */
    .coherent_ram (NOLOAD) : ALIGN(PAGE_SIZE) {
        __COHERENT_RAM_START__ = .;
        *(.tzfw_coherent_mem)
        __COHERENT_RAM_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __COHERENT_RAM_END__ = .;
    } >RAM
#endif /* USE_COHERENT_MEM */

    /*
     * 标记RW段结束，并记录BL1在RAM中的范围。
     */
    __RW_END__ = .;

    __BL1_RAM_START__ = ADDR(.data);
    __BL1_RAM_END__ = .;

    /*
     * 记录.data段在ROM中的起始地址及其大小。
     */
    __DATA_ROM_START__ = LOADADDR(.data);
    __DATA_SIZE__ = SIZEOF(.data);

    /*
     * .data段是最后一个PROGBITS段，其结束标志着BL1在可信ROM中的实际内容结束。
     */
    __BL1_ROM_END__ =  __DATA_ROM_START__ + __DATA_SIZE__;

    /*
     * 断言BL1的ROM内容未超出限制。
     */
    ASSERT(__BL1_ROM_END__ <= BL1_RO_LIMIT,
        "BL1's ROM content has exceeded its limit.")

    /*
     * 记录.bss段的大小。
     */
    __BSS_SIZE__ = SIZEOF(.bss);

#if USE_COHERENT_MEM
    /*
     * 记录相干内存段的实际大小（未对齐部分）。
     */
    __COHERENT_RAM_UNALIGNED_SIZE__ =
        __COHERENT_RAM_END_UNALIGNED__ - __COHERENT_RAM_START__;
#endif /* USE_COHERENT_MEM */

    /*
     * 断言BL1的RW段未超出限制，并标记RAM区域结束。
     */
    ASSERT(. <= BL1_RW_LIMIT, "BL1's RW section has exceeded its limit.")
    RAM_REGION_END = .;
}