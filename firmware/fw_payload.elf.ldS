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

//	PROVIDE(_fw_reloc_end = .);

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

#ifdef FW_PAYLOAD_OFFSET
	. = FW_TEXT_START + FW_PAYLOAD_OFFSET;
#else
	. = ALIGN(FW_PAYLOAD_ALIGN);
#endif

	.payload :
	{
		PROVIDE(_payload_start = .);
		*(.payload)
		. = ALIGN(8);
		PROVIDE(_payload_end = .);
	}

    PROVIDE(_fw_reloc_end = .);

}
