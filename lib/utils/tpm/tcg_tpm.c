#include "sbi/sbi_scratch.h"
#include "sbi/sbi_timer.h"
#include <sbi_utils/tpm/tcg.h>
#include <sbi_utils/tpm/TpmTypes.h>
#include <sbi_utils/tpm/tcg_tpm.h>
#include <sbi_utils/tpm/tpm_driver.h>
#include <sbi_utils/tpm/swap.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static TPMVersion TPM_version;


static void
tpm20_set_timeouts(void)
{
	u32 durations[3] = {
		TPM2_DEFAULT_DURATION_SHORT,
		TPM2_DEFAULT_DURATION_MEDIUM,
		TPM2_DEFAULT_DURATION_LONG,
	};
	u32 timeouts[4] = {
		TIS2_DEFAULT_TIMEOUT_A,
		TIS2_DEFAULT_TIMEOUT_B,
		TIS2_DEFAULT_TIMEOUT_C,
		TIS2_DEFAULT_TIMEOUT_D,
	};

	tpmhw_set_timeouts(timeouts, durations);
}
/*static u32 tpm20_pcr_selection_size;*/
/*static struct tpml_pcr_selection *tpm20_pcr_selection;*/


static int
tpm_simple_cmd(u8 locty, u32 ordinal
               , int param_size, u16 param, enum tpmDurationType to_t)
{
    struct {
        struct tpm_req_header trqh;
        u16 param;
    } __packed req = {
        .trqh.totlen = cpu_to_be32(sizeof(req.trqh) + param_size),
        .trqh.ordinal = cpu_to_be32(ordinal),
        .param = param_size == 2 ? cpu_to_be16(param) : param,
    };
    switch (TPM_version) {
    case TPM_VERSION_1_2:
        req.trqh.tag = cpu_to_be16(TPM_TAG_RQU_CMD);
        break;
    case TPM_VERSION_2:
        req.trqh.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS);
        break;
    }

    u8 obuffer[64];
    struct tpm_rsp_header *trsh = (void*)obuffer;
    u32 obuffer_len = sizeof(obuffer);
	sbi_memset(obuffer, 0x0, sizeof(obuffer));

    int ret = tpmhw_transmit(locty, &req.trqh, obuffer, &obuffer_len, to_t);
    ret = ret ? -1 : be32_to_cpu(trsh->errcode);
    sbi_printf( "Return from tpm_simple_cmd(%x, %x, %x) = %x\n",
            locty, ordinal, param, ret);
    return ret;
}



static int
tpm20_getcapability(u32 capability, u32 property, u32 count,
                    struct tpm_rsp_header *rsp, u32 rsize)
{
    struct tpm2_req_getcapability trg = {
        .hdr.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
        .hdr.totlen = cpu_to_be32(sizeof(trg)),
        .hdr.ordinal = cpu_to_be32(TPM2_CC_GetCapability),
        .capability = cpu_to_be32(capability),
        .property = cpu_to_be32(property),
        .propertycount = cpu_to_be32(count),
    };

    u32 resp_size = rsize;
    int ret = tpmhw_transmit(0, &trg.hdr, rsp, &resp_size,
                             TPM_DURATION_TYPE_SHORT);
	ret = (ret ||
		   rsize < be32_to_cpu(rsp->totlen)) ? -1 : be32_to_cpu(rsp->errcode);

    sbi_printf("TCG TPM : Return value from sending TPM2_CC_GetCapability = 0x%08x\n",
            ret);

    return ret;
}

int tpm20_drtm_operations(u8* data, u32 len){
	u32 rc = 0;
	rc = tpm_hash_start_loc4();
	if(rc != 0){
		return -1;
	}
	sbi_timer_delay_loop(1, 1000, NULL, NULL);
	tpm_senddata_loc4(data, len);
	if(rc != 0){
		return -1;
	}
	sbi_timer_delay_loop(1, 1000, NULL, NULL);
	tpm_hash_end_loc4();
	if(rc != 0){
		return -1;
	}
	return rc;
}

int tpm20_read_pcrs(u8* pcr_indices, u32 count, void* resp_buffer, u32 rsize){

	int rc = 0;

	//Ad-hoc structure that contains the necessary informations.
	//Equivalent to a TPML_PCR_SELECTION filled.
	//Everything has to be made big-endian because this informations is passthrough to libtpms and is reverted by libtpms. Go figure.
	struct {
		struct tpm_req_header trqh;
		uint32_t count;
		struct tpms_pcr_selection param;
		u8 bitmap[3];
	} __packed req = {
		.trqh.tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
		.trqh.totlen = cpu_to_be32(sizeof(struct tpm_req_header) + +sizeof(uint32_t) + sizeof(struct tpms_pcr_selection) + 3*sizeof(u8)),
		.trqh.ordinal = cpu_to_be32(TPM2_CC_PCRRead),
		.count = cpu_to_be32(1),
		.param.hashAlg = cpu_to_be16(TPM2_ALG_SHA256), 
		.param.sizeOfSelect = 3,
		.bitmap = {0, 0, 2}, //PCR 17
	};

	
	struct {
		struct tpm_rsp_header trsh;
		uint32_t pcrUpdateCounter;
		struct tpml_pcr_selection pcrSelectionOut;
		struct tpms_pcr_selection pcrSels;
		u8 bitmap[3];
		struct tpm2_digest_values pcrValues;
		u16 digestSize;
		u8 digest[SHA256_BUFSIZE];
	} __packed resp;

	

	uint32_t obuffer_len = sizeof(resp);


	tpmhw_transmit(4, &req.trqh, &resp, &obuffer_len, TPM_DURATION_TYPE_LONG);

	resp.trsh.tag = be16_to_cpu(resp.trsh.tag);
	/*sbi_printf("%02x", resp.trsh.tag);*/
	resp.trsh.totlen = be32_to_cpu(resp.trsh.totlen);
	/*sbi_printf("%0x", resp.trsh.errcode);*/
	resp.pcrUpdateCounter = be32_to_cpu(resp.pcrUpdateCounter);
	/*sbi_printf("%02x", resp.pcrUpdateCounter);*/
	resp.pcrSelectionOut.count = be32_to_cpu(resp.pcrSelectionOut.count);
	/*sbi_printf("%02x", resp.pcrSelectionOut.count);*/
	resp.pcrSels.hashAlg = be16_to_cpu(resp.pcrSels.hashAlg);
	resp.digestSize = be16_to_cpu(resp.digestSize);

	sbi_printf("Printing PCR17 digest\n");
	for(int i=0; i<SHA256_BUFSIZE; i++) {
		sbi_printf("%02x", resp.digest[i]);
	}
	sbi_printf("\n");

	

	return rc;

}


int tpm20_createLoaded(u32 parentobject, u8* modulus) {
	struct {
		struct tpm2_req_createLoaded inParams;
	} __packed req = {

		.inParams = {
		//Request Header
			.hdr = {
				.tag= cpu_to_be16(TPM2_ST_SESSIONS),
				.totlen = cpu_to_be32(sizeof(req)),
				.ordinal = cpu_to_be32(TPM_CC_CreateLoaded),
			},

			//TPM_RH_HIERARCHY
			.rh_hierarchy = cpu_to_be32(parentobject),
			.authblocksize = cpu_to_be32(sizeof(req.inParams.authblock)),
			.authblock = {
				.handle = cpu_to_be32(TPM2_RS_PW),
				.noncesize = cpu_to_be16(0),
				.contsession = TPM2_YES,
				.pwdsize = cpu_to_be16(64),
				.pwd = {1}
			},

			.inSensitive = {
				.size = cpu_to_be16(sizeof(req.inParams.inSensitive.sensitive)),
				.sensitive = {
					.userAuth = {
						//Dummy password value for accessing object
						.size = cpu_to_be16(64),
						.buffer = {1},
					},
					.data = {
						.size = cpu_to_be16(0),
					}
				}
			},
			.inPublic = {
				.size = cpu_to_be16(sizeof(req.inParams.inPublic.publicArea)),
				//TPMT_PUBLIC
				.publicArea = {
					.hashCategory = cpu_to_be16(TPM_ALG_RSA),
					.namingAlg = cpu_to_be16(TPM_ALG_SHA256),
					//TPMA_OBJECT
					//Sign/encrypt flag + userWithAuth + noDA protection
					/*//https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf page 64*/
					/*//TPMT_PUBLIC.authPolicy (TPM2B_DIGEST)*/
					.objectAttributes.attributes = cpu_to_be32((1<<18) | (1<<16)| (1<<10)| (1<<5) | (1<<6) | (1<<1) | (1<<4)),
					.authPolicy.size = cpu_to_be16(0),
					.rsaParms = {
						.symmetricAlg = cpu_to_be16(TPM_ALG_NULL),
						.scheme.scheme = cpu_to_be16(TPM_ALG_RSASSA),
						.scheme.details = cpu_to_be16(TPM_ALG_SHA384),
						.keyBits = cpu_to_be16((u16) 3072),
						.publicExponent = cpu_to_be32((u32) 65537),
					},
					.public_rsa_key_buffer = cpu_to_be16(0),
				//end of publicArea
				}
			//end of inPublic
			}
		//end of inParams
		}
	//end of req
	};
	struct {
		struct tpm_rsp_header trsh;
		u32 handle;
		u32 parameterSize;
		u16 privateSize;
		u8 encryptedPrivate[286];
		struct tpm2b_public_rsa outPublic; 
		u8 modulus[384];
		/*struct tpm2b_digest creationData; */
	} __packed rsp;

	uint32_t obuffer_len = sizeof(rsp);
	

	tpmhw_transmit(0, &req.inParams.hdr, &rsp, &obuffer_len, TPM_DURATION_TYPE_LONG);

	if (rsp.trsh.errcode) {
	sbi_printf("Response tag is : %02x\nResponse error code is %02x\n", rsp.trsh.tag, rsp.trsh.errcode);
		return -1;
	}

	rsp.trsh.tag = be16_to_cpu(rsp.trsh.tag);
	rsp.trsh.totlen = be32_to_cpu(rsp.trsh.totlen);
	rsp.handle = be32_to_cpu(rsp.handle);

	rsp.parameterSize = be32_to_cpu(rsp.parameterSize);

	rsp.privateSize = be16_to_cpu(rsp.privateSize);

	rsp.outPublic.size = be16_to_cpu(rsp.outPublic.size);
	rsp.outPublic.publicArea.hashCategory = cpu_to_be16(rsp.outPublic.publicArea.hashCategory); 
	rsp.outPublic.publicArea.namingAlg = cpu_to_be16(rsp.outPublic.publicArea.namingAlg);
	rsp.outPublic.publicArea.objectAttributes.attributes = cpu_to_be32(rsp.outPublic.publicArea.objectAttributes.attributes);
	rsp.outPublic.publicArea.authPolicy.size = cpu_to_be32(rsp.outPublic.publicArea.authPolicy.size);
	rsp.outPublic.publicArea.rsaParms.symmetricAlg = cpu_to_be16(rsp.outPublic.publicArea.rsaParms.symmetricAlg),

	rsp.outPublic.publicArea.rsaParms.scheme.scheme = cpu_to_be16(rsp.outPublic.publicArea.rsaParms.scheme.scheme),
	rsp.outPublic.publicArea.rsaParms.keyBits = cpu_to_be16(rsp.outPublic.publicArea.rsaParms.keyBits),
	rsp.outPublic.publicArea.rsaParms.publicExponent = cpu_to_be32(rsp.outPublic.publicArea.rsaParms.publicExponent),
	rsp.outPublic.publicArea.public_rsa_key_buffer = cpu_to_be16(rsp.outPublic.publicArea.public_rsa_key_buffer),


	sbi_printf("\nTag is %02x\n", rsp.trsh.tag);
	sbi_printf("Totlen is %08x\n", rsp.trsh.totlen);
	sbi_printf("Error code is %08x\n", rsp.trsh.errcode);
	sbi_printf("Handle is %08x\n", rsp.handle);
	sbi_printf("Parametersize is: %08x\n", rsp.parameterSize);
	sbi_printf("Private size is: %04x\n", rsp.privateSize);
	sbi_printf("Private area is :\n");
	for(u16 i=0; i<rsp.privateSize; i++){
		sbi_printf("%02x ", rsp.encryptedPrivate[i]);
	}
	sbi_printf("\n");
	sbi_printf("Public size is : %04x\n", rsp.outPublic.size);
	sbi_printf("HashCategory is: %04x\n", rsp.outPublic.publicArea.hashCategory);
	sbi_printf("namingAlg is: %04x\n", rsp.outPublic.publicArea.namingAlg);
	sbi_printf("objectAttributes is: %08x\n", rsp.outPublic.publicArea.objectAttributes.attributes);
	sbi_printf("authPolicy is: %04x\n", rsp.outPublic.publicArea.authPolicy.size);
	sbi_printf("rsaParms.symmetricAlg is: %04x\n", rsp.outPublic.publicArea.rsaParms.symmetricAlg);
	sbi_printf("rsaParms.scheme is: %04x    TPM_ALG_RSASSA is: %04x\n", rsp.outPublic.publicArea.rsaParms.scheme.scheme, TPM_ALG_RSASSA);
	sbi_printf("rsaParms.keyBits is: %04x\n", rsp.outPublic.publicArea.rsaParms.keyBits);
	sbi_printf("rsaParms.publicExponent is: %08x\n", rsp.outPublic.publicArea.rsaParms.publicExponent);
	sbi_printf("keySize is: %04x\n", rsp.outPublic.publicArea.public_rsa_key_buffer);
	sbi_printf("Modulus is:\n0x");
	for(u16 i=0; i<rsp.outPublic.publicArea.public_rsa_key_buffer; i++){
		sbi_printf("%02x", rsp.modulus[i]);
	}
	sbi_printf("\n");


	/*sbi_printf("rsa_key_size is : %u\n", rsp.outPublic.publicArea.public_rsa_key_buffer);*/


	/*sbi_printf("hashCategory is : %x, TPM_ALG_RSA is : %x\n", rsp.outPublic.publicArea.hashCategory, TPM_ALG_RSA);*/
	sbi_memcpy(modulus, (u8*) rsp.modulus, 384);

	return rsp.handle;

}
/* We leave the choice to create primary keys under multiple seeds, i.e. under different authorities */
int tpm20_createPrimary(u32 authority){

	struct {
		struct tpm2_req_createPrimaryRSA inParams;

		/*struct tpms_pcr_selection pcrSel;*/
		/*u8 bitmap[3];*/
	} __packed req = {
		.inParams = {
			.hdr = {
				.tag= cpu_to_be16(TPM2_ST_SESSIONS),
				.totlen = cpu_to_be32(sizeof(req)),
				.ordinal = cpu_to_be32(TPM_CC_CreateLoaded),
			},
			.rh_hierarchy = cpu_to_be32(authority),
			.authblocksize = cpu_to_be32(sizeof(req.inParams.authblock)),
			.authblock = {
				.handle = cpu_to_be32(TPM2_RS_PW),
				.noncesize = cpu_to_be16(0),
				.contsession = TPM2_YES,
				.pwdsize = cpu_to_be16(0),
			},
			.inSensitive = {
				.size = cpu_to_be16(sizeof(req.inParams.inSensitive.sensitive)),
				.sensitive = {
					//TPM2B_SENSITIVE_CREATE
					//Dummy password value for accessing object
					.userAuth.size = cpu_to_be16(64),
					.userAuth.buffer = {1},
					.data.size = cpu_to_be16(64),
					.data.buffer = {1},              			
				}
			},
			.inPublic = {
				.size = cpu_to_be16(sizeof(req.inParams.inPublic.publicArea)),
				.publicArea = {
					.hashCategory = cpu_to_be16(TPM_ALG_RSA),
					.namingAlg = cpu_to_be16(TPM_ALG_SHA256),
					//https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf page 64
					.objectAttributes.attributes = cpu_to_be32((1<<17) | (1<<16)| (1<<6)| (1<<5) | (1<<10) | (1<<1) | (1<<4)),
					//TPMT_PUBLIC.authPolicy (TPM2B_DIGEST)
					.authPolicy.size = cpu_to_be16(0),
					.rsaParms = {
						.symmetricAlg = {
							.algName = cpu_to_be16(TPM_ALG_AES),
							.keyBits = cpu_to_be16(128),
							.algMode = cpu_to_be16(TPM_ALG_CFB),
						},
						.nullAlg = cpu_to_be16(TPM_ALG_NULL),
						.keyBits = cpu_to_be16((u16) 3072),
						.publicExponent = cpu_to_be32((u32) 65537),
					},
					.public_rsa_key_buffer = cpu_to_be16(0),
				//end  of publicArea
				}
			//end of inPublic
			},
		//end of inParams
		}
	//end of req
	};

	struct {
		struct tpm_rsp_header trsh;
		u32 handle;
		u16 privateSize;
		struct tpm2b_public outPublic;
		struct tpm2b_digest creationData; 
	} __packed rsp;

	uint32_t obuffer_len = sizeof(rsp);
	

	tpmhw_transmit(0, &req.inParams.hdr, &rsp, &obuffer_len, TPM_DURATION_TYPE_LONG);

	rsp.trsh.errcode = be32_to_cpu(rsp.trsh.errcode);
	rsp.trsh.tag = be16_to_cpu(rsp.trsh.tag);
	rsp.handle = be32_to_cpu(rsp.handle);

	if (rsp.trsh.errcode) {
	sbi_printf("Response tag is : %02x\nResponse error code is %02x\n", rsp.trsh.tag, rsp.trsh.errcode);
		return -1;
	}
	return rsp.handle;
}

int tpm20_quote(struct quote_verif_info* verif){
	u32 SRK = tpm20_createPrimary(TPM2_RH_OWNER);
	if (SRK == -1) {
		sbi_printf("Error in creating key under endorsment authority\n");
		return -1;
	}
	u8 modulus[384];
	u32 aikHandle = tpm20_createLoaded(SRK, (u8*) modulus);
	if (aikHandle == -1) {
		sbi_printf("Error in creating key under SRK \n");
		return -1;
	}
	struct {
		struct tpm2_req_quote quotePart;
		struct tpms_pcr_selection pcrSelectionIn;
		u8 bitmap[3];

	} __packed req = {
		.quotePart = {
			.hdr = {
				.tag = cpu_to_be16(TPM2_ST_SESSIONS),
				.totlen = cpu_to_be32(sizeof(req)),
				.ordinal = cpu_to_be32(TPM2_CC_Quote),
			},
			.signKeyHandle = cpu_to_be32(aikHandle),
			.authblocksize = cpu_to_be32(sizeof(req.quotePart.authblock)),
			.authblock = {
				.handle = cpu_to_be32(TPM_RS_PW),
				.noncesize = cpu_to_be16(0),
				.contsession = TPM2_YES,
				.pwdsize = cpu_to_be16(64),
				.pwd = {1},
			},
			.qualifyingDatasize = cpu_to_be16(0),
			.algSchemeName = cpu_to_be16(TPM_ALG_NULL),
			.pcrSel = {
				.count = cpu_to_be32(1),
			},
		},
		.pcrSelectionIn = {
			.hashAlg = cpu_to_be16(TPM2_ALG_SHA256),
			.sizeOfSelect = 3
		},
		//PCR 17
		.bitmap = {0, 0, 2}
	};

	//struct {
	//	struct tpm2_quote_rsp rspHead;
	//	u8 bitmap[3];
	//	u16 digestSize;
	//	u8 digest[SHA384_BUFSIZE]; //PCR rehash
	//	struct tpmt_signature_rsa signature;
	//	u8 buffer[5]; //2 bytes for nonce size (0), 1 for session attributes echo, 2 for ack size
	//}__packed rsp;
	struct quote_response rsp;

	uint32_t obuffer_len = sizeof(rsp);

	tpmhw_transmit(0, &req.quotePart.hdr, &rsp, &obuffer_len, TPM_DURATION_TYPE_LONG);

	rsp.rspHead.hdr.tag = be16_to_cpu(rsp.rspHead.hdr.tag);
	rsp.rspHead.hdr.totlen = be32_to_cpu(rsp.rspHead.hdr.totlen);
	rsp.rspHead.hdr.errcode = be32_to_cpu(rsp.rspHead.hdr.errcode);
	if (rsp.rspHead.hdr.errcode) {
	sbi_printf("For Quote: Response tag is : %02x\nResponse error code is %02x\n", rsp.rspHead.hdr.tag, rsp.rspHead.hdr.errcode);
		return -1;
	}
	rsp.rspHead.parameterSize = be32_to_cpu(rsp.rspHead.parameterSize);
	rsp.rspHead.quoted.attestSize= be16_to_cpu(rsp.rspHead.quoted.attestSize);
	rsp.signature.signatureAlgorithm = be16_to_cpu(rsp.signature.signatureAlgorithm);
	rsp.signature.sig.hashAlg = be16_to_cpu(rsp.signature.sig.hashAlg);

	sbi_memcpy(verif->modulus, modulus, 384);
	sbi_memcpy(verif->signature, rsp.signature.sig.signature, 384);
	sbi_memcpy(verif->attestation, (u8*) &(rsp.rspHead.quoted.attestationData), 129);


	return 0;
	}


/* In SeaBIOS, this method is wrapped into a tpm_setup method that handles linkage to the rest of the interface for the BIOS */
int tpm20_startup(void){

	sbi_printf("We are starting the TPM");
	//Determine which interface we're using. TIS is prefered.
	TPM_version = tpmhw_probe();
	if(tpmhw_is_present()){
		sbi_printf("TPM is present and we can set timeouts\n");
		tpm20_set_timeouts();
	}
	int ret = tpm_simple_cmd(0, TPM2_CC_Startup,
							 2, TPM2_SU_CLEAR, TPM_DURATION_TYPE_SHORT);
	sbi_printf("TCG TPM: Return value from sending TPM2_CC_Startup(SU_CLEAR) =0x%08x\n", ret);
	if (ret)
		sbi_printf("ERROR: TPM could not be initialized\n");


    ret = tpm_simple_cmd(0, TPM2_CC_SelfTest,
                         1, TPM2_YES, TPM_DURATION_TYPE_LONG);
	sbi_printf("TCG TPM: Return value from sending TPM2_CC_SelfTest =0x%08x\n", ret);
	if (ret) return -1;

	u8 buffer[128];
	struct tpm2_res_getcapability *trg =
	  (struct tpm2_res_getcapability *)&buffer;
	ret = tpm20_getcapability(TPM2_CAP_PCRS, 0, 8, &trg->hdr,
								  sizeof(buffer));
	if (ret)
		return ret;
	/*ret = tpm20_get_pcrbanks();*/
	
	/*sbi_printf("%u", ((u8 *) tpm20_pcr_selection)[sizeof(struct tpml_pcr_selection  ) + sizeof(u16)]);*/

	if (ret) return -1;
    return 0;
}
