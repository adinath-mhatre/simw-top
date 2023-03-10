/**
 * @file azure_provisioning.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * azure provisioning file
 */
#include "sm_types.h"

/* clang-format off */
/*******************************************************************
* INCLUDE FILES
*******************************************************************/
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "provisioning.h"
#include "aws_iot_config.h"
#if SSS_HAVE_SSS
#include <fsl_sss_api.h>
#include <fsl_sss_sscp.h>

#endif
#if SSS_HAVE_MBEDTLS_ALT_A71CH
#  include "ax_mbedtls.h"
#  include <fsl_sscp_a71ch.h>
#endif
#if SSS_HAVE_MBEDTLS_ALT_SSS
#  include "sss_mbedtls.h"
#  include "ex_sss.h"
#endif
#include "nxLog_App.h"

/* clang-format off */
const uint8_t client_key[] = { \
0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
0x01, 0x01, 0x04, 0x20,
0xb6, 0xe3, 0x2c, 0x56, 0x78, 0x76, 0xae, 0xf9, 0xa2, 0xe8, 0x32, 0x38, 0x3c, 0x8c,
0xc4, 0x89, 0x63, 0xf1, 0xae, 0x9e, 0x22, 0xa3, 0x45, 0x4b, 0x89, 0x81, 0x50, 0x65, 0x60,
0x87, 0x1b, 0xf9,
0xA1, 0x44, 0x03, 0x42, 0x00,
0x04, 0x62, 0x6a, 0x1a, 0x2b, 0x03, 0x41, 0x4d, 0x7e, 0xbf, 0x9a, 0x68, 0x27, 0x89, 0xbc,
0x35, 0x76, 0x86, 0x9d, 0x9e, 0xb0, 0x09, 0xfc, 0x01, 0x09, 0x95, 0xb7, 0x9e, 0xf5, 0x68,
0xf3, 0x47, 0x83, 0xad, 0x3c, 0x71, 0x24, 0x79, 0x3a, 0x9b, 0xb4, 0xd5, 0xc5, 0x05, 0x44,
0x4d, 0x43, 0x46, 0xa8, 0xd7, 0xa4, 0x2e, 0xd9, 0xa3, 0xde, 0x49, 0x13, 0xcb, 0x67, 0xdd,
0x68, 0x82, 0xd9, 0x4c, 0x28,
};

const uint8_t client_cer[] = { \
0x30, 0x82, 0x01, 0x6D, 0x30, 0x82, 0x01, 0x13, 0xA0, 0x03, 0x02,
0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x32, 0x31, 0x30, 0x30,
0x2E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x27, 0x4E, 0x58, 0x50,
0x20, 0x53, 0x65, 0x6D, 0x69, 0x63, 0x6F, 0x6E, 0x64, 0x75, 0x63,
0x74, 0x6F, 0x72, 0x73, 0x20, 0x37, 0x30, 0x30, 0x32, 0x38, 0x30,
0x30, 0x34, 0x30, 0x31, 0x32, 0x30, 0x35, 0x31, 0x39, 0x38, 0x39,
0x30, 0x35, 0x33, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x38, 0x30, 0x34,
0x31, 0x36, 0x30, 0x36, 0x33, 0x34, 0x34, 0x35, 0x5A, 0x17, 0x0D,
0x32, 0x38, 0x30, 0x34, 0x31, 0x33, 0x30, 0x36, 0x33, 0x34, 0x34,
0x35, 0x5A, 0x30, 0x32, 0x31, 0x30, 0x30, 0x2E, 0x06, 0x03, 0x55,
0x04, 0x03, 0x0C, 0x27, 0x4E, 0x58, 0x50, 0x20, 0x53, 0x65, 0x6D,
0x69, 0x63, 0x6F, 0x6E, 0x64, 0x75, 0x63, 0x74, 0x6F, 0x72, 0x73,
0x20, 0x37, 0x30, 0x30, 0x32, 0x38, 0x30, 0x30, 0x34, 0x30, 0x31,
0x32, 0x30, 0x35, 0x31, 0x39, 0x38, 0x39, 0x30, 0x35, 0x33, 0x30,
0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
0x03, 0x42, 0x00, 0x04, 0x62, 0x6A, 0x1A, 0x2B, 0x03, 0x41, 0x4D,
0x7E, 0xBF, 0x9A, 0x68, 0x27, 0x89, 0xBC, 0x35, 0x76, 0x86, 0x9D,
0x9E, 0xB0, 0x09, 0xFC, 0x01, 0x09, 0x95, 0xB7, 0x9E, 0xF5, 0x68,
0xF3, 0x47, 0x83, 0xAD, 0x3C, 0x71, 0x24, 0x79, 0x3A, 0x9B, 0xB4,
0xD5, 0xC5, 0x05, 0x44, 0x4D, 0x43, 0x46, 0xA8, 0xD7, 0xA4, 0x2E,
0xD9, 0xA3, 0xDE, 0x49, 0x13, 0xCB, 0x67, 0xDD, 0x68, 0x82, 0xD9,
0x4C, 0x28, 0xA3, 0x1A, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55,
0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B, 0x06, 0x03, 0x55,
0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0A, 0x06,
0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48,
0x00, 0x30, 0x45, 0x02, 0x20, 0x76, 0xBA, 0x24, 0xAC, 0xF2, 0xFC,
0x81, 0x26, 0xB3, 0x0B, 0xCE, 0x6E, 0x59, 0x7C, 0x5F, 0x6B, 0x3E,
0x3E, 0x7E, 0x36, 0xCE, 0x0F, 0x32, 0x51, 0x57, 0x5F, 0x4D, 0x34,
0x7A, 0x8B, 0xF9, 0x69, 0x02, 0x21, 0x00, 0xAB, 0xBC, 0x65, 0xAF,
0x09, 0x39, 0x57, 0x83, 0x64, 0x24, 0x64, 0x74, 0xA3, 0xA0, 0x50,
0x9F, 0x3F, 0xA4, 0xD4, 0x0E, 0x60, 0xD6, 0xE3, 0x1B, 0x78, 0x22,
0x2F, 0xFB, 0x33, 0xA5, 0x75, 0x7A,
};

/* clang-format on */

static sss_status_t add_key(sss_object_t *keyObject,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    const uint8_t *buff,
    size_t buff_size,
    size_t keyBitLen,
    uint32_t keyId,
    uint32_t options,
    sss_key_store_t *pKs)
{
    sss_status_t status = kStatus_SSS_Success;

    status = sss_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        LOG_I(" sss_key_object_init Failed ");
        goto exit;
    }

    status = sss_key_object_allocate_handle(keyObject, keyId, keyPart, cipherType, buff_size, options);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_object_allocate_handle Failed ");
        goto exit;
    }

    status = sss_key_store_set_key(pKs, keyObject, buff, buff_size, keyBitLen, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_set_key Failed ");
        goto exit;
    }
exit:
    return status;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
#if SSS_HAVE_SSS
    sss_status_t status;
#endif

    sss_object_t obj_kp = {0}, obj_client_cert = {0};

    status = add_key(&obj_kp,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        client_key,
        sizeof(client_key),
        256,
        SSS_KEYPAIR_INDEX_CLIENT_PRIVATE,
        kKeyObject_Mode_Persistent,
        &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_E(" for key pair ... \n");
        goto exit;
    }

    status = add_key(&obj_client_cert,
        kSSS_KeyPart_Default,
        kSSS_CipherType_Binary,
        client_cer,
        sizeof(client_cer),
        sizeof(client_cer) * 8,
        SSS_CERTIFICATE_INDEX_CLIENT,
        kKeyObject_Mode_Persistent,
        &pCtx->ks);
    if (status != kStatus_SSS_Success) {
        LOG_E(" for client certificate ... \n");
        goto exit;
    }

    LOG_I(" PROVISIONING SUCCESSFUL!!!");
exit:
    LOG_I("Provisioning Example Finished");
    return status;
}
