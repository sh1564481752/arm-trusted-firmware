// ...existing code...
/*
 * 版权所有 (c) 2016-2025, Arm Limited and Contributors。保留所有权利。
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/bl_common.ld.h>
#include <lib/per_cpu/per_cpu_defs.h>
#include <lib/xlat_tables/xlat_tables_defs.h>

OUTPUT_FORMAT(elf32-littlearm)
OUTPUT_ARCH(arm)
ENTRY(sp_min_vector_table)

MEMORY {
    RAM (rwx): ORIGIN = BL32_BASE, LENGTH = BL32_LIMIT - BL32_BASE
}

#ifdef PLAT_SP_MIN_EXTRA_LD_SCRIPT
#   include <plat_sp_min.ld.S>
#endif /* PLAT_SP_MIN_EXTRA_LD_SCRIPT */

SECTIONS {
    RAM_REGION_START = ORIGIN(RAM);
    RAM_REGION_LENGTH = LENGTH(RAM);
    . = BL32_BASE;

    ASSERT(. == ALIGN(PAGE_SIZE),
        "BL32_BASE 地址未按页边界对齐。")

#if SEPARATE_CODE_AND_RODATA
    .text . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".text 地址未按页边界对齐。");

        __TEXT_START__ = .;

        *entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(.vectors)
        __TEXT_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __TEXT_END__ = .;
    } >RAM

    /* .ARM.extab 和 .ARM.exidx 仅因 Clang 需要而添加 */
    .ARM.extab . : {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } >RAM

    .ARM.exidx . : {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } >RAM

    .rodata . : {
        __RODATA_START__ = .;
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        . = ALIGN(8);

#   include <lib/el3_runtime/pubsub_events.h>
        __RODATA_END_UNALIGNED__ = .;

        . = ALIGN(PAGE_SIZE);

        __RODATA_END__ = .;
    } >RAM
#else /* SEPARATE_CODE_AND_RODATA */
    .ro . : {
        ASSERT(. == ALIGN(PAGE_SIZE),
        ".ro 地址未按页边界对齐。");

        __RO_START__ = .;

        *entrypoint.o(.text*)
        *(SORT_BY_ALIGNMENT(.text*))
        *(SORT_BY_ALIGNMENT(.rodata*))

        RODATA_COMMON

        . = ALIGN(8);

#   include <lib/el3_runtime/pubsub_events.h>

        *(.vectors)

        __RO_END_UNALIGNED__ = .;

        /*
         * 映射到此段的内存页将被标记为 device 内存。不要在此处混入其他未预期的数据。
         * 确保当前内存页的其余部分为空闲。
         */
        . = ALIGN(PAGE_SIZE);

        __RO_END__ = .;
    } >RAM
#endif /* SEPARATE_CODE_AND_RODATA */

    ASSERT(__CPU_OPS_END__ > __CPU_OPS_START__,
        "未为此平台定义 cpu_ops。")

    __RW_START__ = .;

    DATA_SECTION >RAM
    RELA_SECTION >RAM

#ifdef BL32_PROGBITS_LIMIT
    ASSERT(. <= BL32_PROGBITS_LIMIT, "BL32 progbits 超出限制。")
#endif /* BL32_PROGBITS_LIMIT */

    STACK_SECTION >RAM
    BSS_SECTION >RAM
    PER_CPU >RAM
    XLAT_TABLE_SECTION >RAM

    __BSS_SIZE__ = SIZEOF(.bss);

#if USE_COHERENT_MEM
    /*
     * coherent 内存段的基址必须按页对齐，以保证 coherent 数据占据独立页面，
     * 不与普通数据混在一起。这对于为 coherent 数据设置正确的页表属性是必要的。
     */
    .coherent_ram (NOLOAD) : ALIGN(PAGE_SIZE) {
        __COHERENT_RAM_START__ = .;

        /*
         * Bakery 锁存放在 coherent 内存中。每个锁的数据是连续的并由编译器完全分配。
         */
        *(.bakery_lock)
        *(.tzfw_coherent_mem)

        __COHERENT_RAM_END_UNALIGNED__ = .;

        /*
         * 映射到此段的内存页将被标记为 device 内存。不要混入其他未预期的数据。
         * 确保当前内存页的其余部分为空闲。
         */
        . = ALIGN(PAGE_SIZE);

        __COHERENT_RAM_END__ = .;
    } >RAM

    __COHERENT_RAM_UNALIGNED_SIZE__ =
        __COHERENT_RAM_END_UNALIGNED__ - __COHERENT_RAM_START__;
#endif /* USE_COHERENT_MEM */

    __RW_END__ = .;
    __BL32_END__ = .;

    /DISCARD/ : {
        *(.dynsym .dynstr .hash .gnu.hash)
    }

    ASSERT(. <= BL32_LIMIT, "BL32 镜像超出其限制。")
    RAM_REGION_END = .;
}
// ...existing code...