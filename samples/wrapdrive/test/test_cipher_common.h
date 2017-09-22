#ifndef __TEST_CIPHY_COMMON__
#define __TEST_CIPHY_COMMON__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "../../../include/uapi/linux/vfio.h"
#include "wd.h"
#include "wd_cipher.h"


#define SYS_ERR_COND(cond, msg) if(cond) { \
	perror(msg); \
	exit(EXIT_FAILURE); }

unsigned char aucDataIn_aes_cbc_128[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
unsigned char aucKey_aes_cbc_128[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
unsigned char aucDataOut_aes_cbc_128[] = {
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
unsigned char aucIvIn_aes_cbc_128[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

//#define ALG WD_CY_SYM_ALG(WD_CA_DES, WD_CM_ECB)

static inline void init_capa(struct wd_capa *capa, char *alg)
{

	struct wd_aalg_calg_param *calg = (struct wd_aalg_calg_param *)capa->priv;

	memset(capa, 0, sizeof(*capa));
	capa->alg = alg;
	calg->cparam.key_size = sizeof(aucKey_aes_cbc_128);
	calg->cparam.iv_size= sizeof(aucIvIn_aes_cbc_128);
}

static inline void init_msg(struct wd_cipher_msg *msg, struct wd_capa *capa)
{
	memset(msg, 0, sizeof(*msg));
	msg->keylen = sizeof(aucKey_aes_cbc_128);
	msg->alg = capa->alg;
	msg->status = 0;
	msg->dsize = (__u32)sizeof(aucDataIn_aes_cbc_128);
	msg->optype = WD_CIPHER_ENCRYPT;
}

static inline void check_result(void *result)
{
	if (memcmp(result, aucDataOut_aes_cbc_128, sizeof(aucDataOut_aes_cbc_128)))
		printf("test fail\n");
	else
		printf("test success\n");
}

static inline void dump_buf(unsigned char *buf, int len)
{
	int i;

	printf("buf = %p, len = %d\n", buf, len);
	for (i = 1; i <= len; i++) {
		printf("%02x ", *(buf++));
		if ((i % 10 == 0))
			printf("\n");
	}

	printf("\n");
}

#endif
