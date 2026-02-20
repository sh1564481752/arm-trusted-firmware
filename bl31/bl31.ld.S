/*
 * Copyright (c) 2013-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/bl_common.ld.h>
#include <lib/per_cpu/per_cpu_defs.h>
#include <lib/xlat_tables/xlat_tables_defs.h>

/* 
 * 设置输出格式和架构，并指定入口点。
 */
OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(PLATFORM_LINKER_ARCH)
ENTRY(bl31_entrypoint)

/*
 * 定义内存区域，包括RAM、NOBITS和RWDATA区域。
 * 根据配置选项决定是否分离NOBITS和RWDATA区域。
 */
MEMORY {
    RAM (rwx): ORIGIN = BL31_BASE, LENGTH = BL31_LIMIT - BL31_BASE

#if SEPARATE_NOBITS_REGION
    NOBITS (rw!a): ORIGIN = BL31_NOBITS_BASE, LENGTH = BL31_NOBITS_LIMIT - BL31_NOBITS_BASE
#else /* SEPARATE_NOBITS_REGION */
#   define NOBITS RAM
#endif /* SEPARATE_NOBITS_REGION */

#if SEPARATE_RWDATA_REGION
    RAM_RW (rw): ORIGIN = BL31_RWDATA_BASE, LENGTH = BL31_RWDATA_LIMIT - BL31_RWDATA_BASE
#else /* SEPARATE_RWDATA_REGION */
#define RAM_RW RAM
#endif /* SEPARATE_RWDATA_REGION */
}

/*
 * 如果定义了PLAT_EXTRA_LD_SCRIPT，则包含平台特定的链接脚本。
 */
#if PLAT_EXTRA_LD_SCRIPT
#   include <plat.ld.S>
#endif /* PLAT_EXTRA_LD_SCRIPT */

/*
 * 定义各个段的布局，包括.text、.rodata、.data、.bss等。
 * 根据配置选项决定是否分离代码和只读数据段。
 */
SECTIONS {
    RAM_REGION_START = ORIGIN(RAM);
    RAM_REGION_LENGTH = LENGTH(RAM);
    . = BL31_BASE;

    /*
     * 断言检查BL31_BASE地址是否按页对齐。
     */
    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL31_BASE address is not aligned on a page boundary.")

    __BL31_START__ = .;

#if SEPARATE_CODE_AND_RODATA
    /*
     * 分离代码段和只读数据段。
     * 代码段包含入口点和向量表，只读数据段包含常量数据。
     */
    .text . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".text is not aligned on a page boundary.");

        __TEXT_START__ = .;

        *bl31_entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(SORT(.text*)))
        *(.vectors)
        __TEXT_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __TEXT_END__ = .;
    } >RAM

    .rodata . : {
        __RODATA_START__ = .;

        *(SORT_BY_ALIGNMENT(.rodata*))

#   if PLAT_EXTRA_RODATA_INCLUDES
#       include <plat.ld.rodata.inc>
#   endif /* PLAT_EXTRA_RODATA_INCLUDES */

        RODATA_COMMON

        . = ALIGN(8);

#   include <lib/el3_runtime/pubsub_events.h>
        __RODATA_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __RODATA_END__ = .;
    } >RAM
#else /* SEPARATE_CODE_AND_RODATA */
    /*
     * 不分离代码段和只读数据段，将它们合并到一个段中。
     */
    .ro . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".ro is not aligned on a page boundary.");

        __RO_START__ = .;

        *bl31_entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        . = ALIGN(8);

#   include <lib/el3_runtime/pubsub_events.h>

        *(.vectors)

        __RO_END_UNALIGNED__ = .;

        /*
         * 内存页面映射到此段将被标记为只读可执行。
         * 确保当前内存页面的其余部分未被使用。
         */
        . = ALIGN(PAGE_SIZE);

        __RO_END__ = .;
    } >RAM
#endif /* SEPARATE_CODE_AND_RODATA */

    /*
     * 断言检查cpu_ops是否已定义。
     */
    ASSERT(__CPU_OPS_END__ > __CPU_OPS_START__,
        "cpu_ops not defined for this platform.")

#if SPM_MM || (SPMC_AT_EL3 && SPMC_AT_EL3_SEL0_SP)
#   ifndef SPM_SHIM_EXCEPTIONS_VMA
#       define SPM_SHIM_EXCEPTIONS_VMA RAM
#   endif /* SPM_SHIM_EXCEPTIONS_VMA */

    /*
     * SPM shim层的异常向量表。必须按2K地址对齐，
     * 但需要将其放置在单独的页面中以便设置独立权限。
     */
    .spm_shim_exceptions : ALIGN(PAGE_SIZE) {
        __SPM_SHIM_EXCEPTIONS_START__ = .;

        *(.spm_shim_exceptions)

        . = ALIGN(PAGE_SIZE);

        __SPM_SHIM_EXCEPTIONS_END__ = .;
    } >SPM_SHIM_EXCEPTIONS_VMA AT>RAM

    PROVIDE(__SPM_SHIM_EXCEPTIONS_LMA__ = LOADADDR(.spm_shim_exceptions));

    . = LOADADDR(.spm_shim_exceptions) + SIZEOF(.spm_shim_exceptions);
#endif /* SPM_MM || (SPMC_AT_EL3 && SPMC_AT_EL3_SEL0_SP) */

#if SEPARATE_RWDATA_REGION
    /*
     * 如果分离RWDATA区域，则重新定位到BL31_RWDATA_BASE。
     */
    . = BL31_RWDATA_BASE;
    ASSERT(BL31_RWDATA_BASE == ALIGN(PAGE_SIZE),
           "BL31_RWDATA_BASE address is not aligned on a page boundary.")

    __RW_START__ = . ;

    DATA_SECTION >RAM_RW AT>RAM
    __DATA_RAM_START__ = __DATA_START__;
    __DATA_RAM_END__ = __DATA_END__;
    __DATA_ROM_START__ = LOADADDR(.data);

    . = ALIGN(PAGE_SIZE);
    __RW_END__ = .;

    RELA_SECTION >RAM
#else /* SEPARATE_RWDATA_REGION */
    __RW_START__ = . ;

    DATA_SECTION >RAM
    RELA_SECTION >RAM
#endif /* SEPARATE_RWDATA_REGION */

#ifdef BL31_PROGBITS_LIMIT
    /*
     * 检查BL31程序位是否超出限制。
     */
    ASSERT(
        . <= BL31_PROGBITS_LIMIT,
        "BL31 progbits has exceeded its limit. Consider disabling some features."
    )
#endif /* BL31_PROGBITS_LIMIT */

#if SEPARATE_NOBITS_REGION
    /*
     * 如果分离NOBITS区域，则重新定位到BL31_NOBITS_BASE。
     */
    . = ALIGN(PAGE_SIZE);

#if !SEPARATE_RWDATA_REGION
    __RW_END__ = .;
#endif /* SEPARATE_RWDATA_REGION */
    __BL31_END__ = .;

    ASSERT(. <= BL31_LIMIT, "BL31 image has exceeded its limit.")

    . = BL31_NOBITS_BASE;

    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL31 NOBITS base address is not aligned on a page boundary.")

    __NOBITS_START__ = .;
#endif /* SEPARATE_NOBITS_REGION */

    /*
     * 定义栈、BSS、每CPU数据和页表段。
     */
    STACK_SECTION >NOBITS
    BSS_SECTION >NOBITS
    PER_CPU >NOBITS
    XLAT_TABLE_SECTION >NOBITS

#if USE_COHERENT_MEM
    /*
     * 定义一致性内存段，用于存储bakery锁和其他一致性数据。
     * 基地址必须按页对齐以确保正确的内存属性设置。
     */
    .coherent_ram (NOLOAD) : ALIGN(PAGE_SIZE) {
        __COHERENT_RAM_START__ = .;

        *(.bakery_lock)
        *(.tzfw_coherent_mem)

        __COHERENT_RAM_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __COHERENT_RAM_END__ = .;
    } >NOBITS
#endif /* USE_COHERENT_MEM */

#if SEPARATE_NOBITS_REGION
    __NOBITS_END__ = .;

    ASSERT(. <= BL31_NOBITS_LIMIT, "BL31 NOBITS region has exceeded its limit.")
#else /* SEPARATE_NOBITS_REGION */
#if !SEPARATE_RWDATA_REGION
    __RW_END__ = .;
#endif /* SEPARATE_RWDATA_REGION */
    __BL31_END__ = .;

    ASSERT(. <= BL31_LIMIT, "BL31 image has exceeded its limit.")
#endif /* SEPARATE_NOBITS_REGION */
    RAM_REGION_END = .;

    /*
     * 丢弃动态符号表和哈希表等不需要的段。
     */
    /DISCARD/ : {
        *(.dynsym .dynstr .hash .gnu.hash)
    }
}