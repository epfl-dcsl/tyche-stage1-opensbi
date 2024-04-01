#ifndef TCGBIOS_H
#define TCGBIOS_H

#include <sbi/sbi_types.h>
#include "TpmTypes.h"
#include "tcg_tpm.h"
#include "tcg.h"

#define TPM_VERSION 0

struct quote_response{
	struct tpm2_quote_rsp rspHead;
	u8 bitmap[3];
	u16 digestSize;
	u8 digest[SHA384_BUFSIZE];
	struct tpmt_signature_rsa signature;
	u8 buffer[5];

} __packed;

void tpm_setup(void);
void tpm_prepboot(void);
void tpm_s3_resume(void);
void tpm_add_bcv(u32 bootdrv, const u8 *addr, u32 length);
void tpm_add_cdrom(u32 bootdrv, const u8 *addr, u32 length);
void tpm_add_cdrom_catalog(const u8 *addr, u32 length);
void tpm_option_rom(const void *addr, u32 len);
int tpm_can_show_menu(void);
void tpm_menu(void);
int tpm20_startup(void);
int tpm20_drtm_operations(u8* data, u32 len);
int tpm20_read_pcrs(u8* pcr_indices, u32 count, void* resp_buffer, u32 rsize);
int tpm20_quote(struct quote_response* rsp);

#endif /* TCGBIOS_H */
