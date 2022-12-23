/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
	#include "fw_base.ldS"

/*
#ifdef TYCHE_SM_OFFSET
        . = FW_TEXT_START + TYCHE_SM_OFFSET;
#else
        . = ALIGN(FW_PAYLOAD_ALIGN);
#endif

        .tyche :
        {
                PROVIDE(_tyche_start = .);
                *(.tyche)
                . = ALIGN(8);
                PROVIDE(_tyche_end = .);
        }
*/
	PROVIDE(_fw_reloc_end = .);
}
