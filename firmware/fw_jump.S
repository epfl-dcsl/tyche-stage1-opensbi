/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include "fw_base.S"

	.section .entry, "ax", %progbits
	.align 3
	.global fw_boot_hart
	/*
	 * This function is called very early even before
	 * fw_save_info() is called.
	 * We can only use a0, a1, and a2 registers here.
	 * The boot HART id should be returned in 'a0'.
	 */
fw_boot_hart:
	li	a0, -1
	ret

	.section .entry, "ax", %progbits
	.align 3
	.global fw_save_info
	/*
	 * We can only use a0, a1, a2, a3, and a4 registers here.
	 * The a0, a1, and a2 registers will be same as passed by
	 * previous booting stage.
	 * Nothing to be returned here.
	 */
fw_save_info:
	ret

	.section .entry, "ax", %progbits
	.align 3
	.global fw_next_arg1
	/*
	 * We can only use a0, a1, and a2 registers here.
	 * The a0, a1, and a2 registers will be same as passed by
	 * previous booting stage.
	 * The next arg1 should be returned in 'a0'.
	 */
fw_next_arg1:
#ifdef FW_JUMP_FDT_ADDR
	li	a0, FW_JUMP_FDT_ADDR
#else
	add	a0, a1, zero
#endif
	ret

	.section .entry, "ax", %progbits
	.align 3
	.global fw_next_addr
	/*
	 * We can only use a0, a1, and a2 registers here.
	 * The next address should be returned in 'a0'.
	 */
fw_next_addr:
	lla	a0, _jump_addr
	REG_L	a0, (a0)
	ret

	.section .entry, "ax", %progbits
	.align 3
	.global fw_next_mode
	/*
	 * We can only use a0, a1, and a2 registers here.
	 * The next address should be returned in 'a0'
	 */
fw_next_mode:
	li	a0, PRV_S
	ret

	.section .entry, "ax", %progbits
	.align 3
	.global fw_options
	/*
	 * We can only use a0, a1, and a2 registers here.
	 * The 'a4' register will have default options.
	 * The next address should be returned in 'a0'.
	 */
fw_options:
	add	a0, zero, zero
	ret

        .section .entry, "ax", %progbits
        .align 3
        .global tyche_sm_addr

        /*
         * We can only use a0, a1, and a2 registers here.
         * Tyche sm address should be returned in 'a0'.
         */
tyche_sm_addr:
        lla     a0, tyche_sm_bin
        ret

        .section .entry, "ax", %progbits
        .align 3
        .global tyche_sm_mode
        /*
         * We can only use a0, a1, and a2 registers here.
         * The Tyche sm mode should be returned in 'a0'.
         */
tyche_sm_mode:
        li      a0, PRV_M
        ret

        .section .tyche
        .align 4
        .globl tyche_sm_bin
tyche_sm_bin:
#ifndef TYCHE_SM_PATH
        wfi
        j       tyche_sm_bin
#else
        .incbin TYCHE_SM_PATH
#endif

#ifndef FW_JUMP_ADDR
#error "Must define FW_JUMP_ADDR"
#endif

	.section .entry, "ax", %progbits
	.align 3
_jump_addr:
	RISCV_PTR FW_JUMP_ADDR
