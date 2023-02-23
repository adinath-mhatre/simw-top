/**
 * @file sssProvider_store.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for file store to decode key labels
 *
 */

/* ********************** Include files ********************** */
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include "sssProvider_main.h"

/* ********************** Private funtions ******************* */

static void *sss_store_object_open(void *provctx, const char *uri)
{
    sss_provider_store_obj_t *pStoreCtx;
    char *baseuri           = NULL;
    char *endptr            = NULL;
    unsigned long int value = 0;

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    baseuri = OPENSSL_strdup(uri);
    if (baseuri == NULL) {
        OPENSSL_free(pStoreCtx);
        return NULL;
    }

    // converting string str  to unsigned long int value base on the base
    // extracting the keyid from the uri nxp:0xxxxxxxxx"
    value = strtoul((baseuri + 4), &endptr, 16);
    if (*endptr != 0 || value > UINT32_MAX) {
        OPENSSL_free(pStoreCtx);
        OPENSSL_free(baseuri);
        return NULL;
    }

    pStoreCtx->keyid    = value;
    pStoreCtx->pProvCtx = provctx;
    pStoreCtx->isFile   = 0;
    return pStoreCtx;
}

static int sss_store_object_load(
    void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)ctx;
    sss_status_t status                 = kStatus_SSS_Fail;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *keytype;

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (pStoreCtx->object.cipherType == kSSS_CipherType_EC_NIST_P ||
        pStoreCtx->object.cipherType == kSSS_CipherType_EC_BRAINPOOL ||
        pStoreCtx->object.cipherType == kSSS_CipherType_EC_NIST_K) {
        keytype = "EC";
    }
    else if (pStoreCtx->object.cipherType == kSSS_CipherType_RSA ||
             pStoreCtx->object.cipherType == kSSS_CipherType_RSA_CRT) {
        keytype = "RSA";
    }
    else {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pStoreCtx, sizeof(pStoreCtx));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
cleanup:
    return 0;
}

static int sss_store_object_eof(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)ctx;

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->object.keyId == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

static int sss_store_object_close(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return 1;
}

const OSSL_DISPATCH sss_store_object_functions[] = {{OSSL_FUNC_STORE_OPEN, (void (*)(void))sss_store_object_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))sss_store_object_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))sss_store_object_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))sss_store_object_close},
    {0, NULL}};
