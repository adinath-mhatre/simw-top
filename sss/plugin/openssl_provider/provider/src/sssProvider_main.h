/**
 * @file sssProvider_main.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef SSS_PROVIDER_MAIN_H
#define SSS_PROVIDER_MAIN_H

/* ********************** Include files ********************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include <limits.h>
/* Openssl includes */
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
/* PnT includes */
#include <fsl_sss_api.h>
#include <se05x_APDU.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include "ex_sss_boot.h"

/* ********************** Constants ************************** */
/* Debug macros */
#define LOG_FLOW_MASK 0x01
#define LOG_DBG_MASK 0x02
#define LOG_ERR_MASK 0x04

#define LOG_FLOW_ON 0x01
#define LOG_DBG_ON 0x02
#define LOG_ERR_ON 0x04

// Signature to indicate that the RSA/ECC key is a reference to a key stored in the Secure Element
#define SIGNATURE_REFKEY_ID 0xA5A6B5B6

/* ********************** structure definition *************** */

typedef struct
{
    const OSSL_CORE_HANDLE *core;
    ex_sss_boot_ctx_t *p_ex_sss_boot_ctx;
} sss_provider_context_t;

typedef struct
{
    int keyid;
    uint16_t key_len;
    uint16_t maxSize;
    sss_object_t object;
    bool isFile;
    FILE *pFile;
    EVP_PKEY *pEVPPkey;
    sss_provider_context_t *pProvCtx;
    bool isPrivateKey;
} sss_provider_store_obj_t;

/* ********************** Function Prototypes **************** */

void sssProv_Print(int flag, const char *format, ...);
void sssProv_PrintPayload(int flag, const U8 *pPayload, U16 nLength, const char *title);

int SSS_CMP_STR(const char* s1, const char* s2);

#endif /* SSS_PROVIDER_H */