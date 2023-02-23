/**
 * @file sssProvider_file_store.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for file store to decode reference keys or openssl keys
 *
 */

/* ********************** Include files ********************** */
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/pem.h>
#include "sssProvider_main.h"

/* ********************** Private funtions ******************* */

static void *sss_file_store_object_open(void *provctx, const char *uri)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = NULL;

    if (uri == NULL) {
        return NULL;
    }

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    pStoreCtx->isFile   = 1;
    pStoreCtx->pProvCtx = provctx;

    // Opening the pem file
    pStoreCtx->pFile = fopen(uri, "rb");
    if (pStoreCtx->pFile == NULL) {
        OPENSSL_clear_free(pStoreCtx, sizeof(sss_provider_store_obj_t));
        pStoreCtx = NULL;
    }

    return pStoreCtx;
}

#define USE_OSSL_PARAM_CALLS 1

static int sss_handle_ecc_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey)
{
    int ret                       = 1;
    size_t i                      = 0;
    sss_status_t status           = kStatus_SSS_Fail;
    unsigned char privKeyBuf[256] = {
        0,
    };
    size_t privKeyLen = 0;
    U32 Coeff[2]      = {0, 0};

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEVPKey != NULL);

#if USE_OSSL_PARAM_CALLS
    {
        int j = 0;
        OSSL_PARAM params[2];
        int openssl_ret = 0;

        params[0]   = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privKeyBuf[0], sizeof(privKeyBuf));
        params[1]   = OSSL_PARAM_construct_end();
        openssl_ret = EVP_PKEY_get_params(pEVPKey, params);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        privKeyLen = params[0].data_size;

        for (size_t start = 0, end = privKeyLen - 1; start < end; start++, end--) {
            unsigned char temp = privKeyBuf[start];
            privKeyBuf[start]  = privKeyBuf[end];
            privKeyBuf[end]    = temp;
        }

        for (j = 0; j < 2; j++) {
            for (i = 3; i < 7; i++) {
                Coeff[j] |= privKeyBuf[privKeyLen - i - (j * 4)] << 8 * (i - 3);
            }
        }

        if (((unsigned int)Coeff[0] == (unsigned int)SIGNATURE_REFKEY_ID) &&
            ((unsigned int)Coeff[1] == (unsigned int)SIGNATURE_REFKEY_ID)) {
            j = 2;
            for (i = 3; i < 7; i++) {
                pStoreCtx->keyid |= privKeyBuf[privKeyLen - i - (j * 4)] << 8 * (i - 3);
            }
        }
        else {
            // Not a reference key
            goto cleanup;
        }
    }

#else
    {
        size_t index               = 0;
        unsigned char *pPrivKeyBuf = &privKeyBuf[0];
        privKeyLen                 = i2d_PrivateKey(pEVPKey, &pPrivKeyBuf);
        ENSURE_OR_GO_CLEANUP(privKeyLen > 0);

        for (i = 0; i < (privKeyLen - 4); i++) {
            // get the reference key signature id (first part)
            Coeff[0] =
                (privKeyBuf[i] << 24) | (privKeyBuf[i + 1] << 16) | (privKeyBuf[i + 2] << 8) | (privKeyBuf[i + 3]);
            if ((unsigned int)Coeff[0] == (unsigned int)SIGNATURE_REFKEY_ID) {
                index = i - 4;
                break;
            }
        }

        if (index == 0) {
            // Not a ref key
            goto cleanup;
        }

        // get the reference key signature id (second part)
        i        = i + 4;
        Coeff[1] = (privKeyBuf[i] << 24) | (privKeyBuf[i + 1] << 16) | (privKeyBuf[i + 2] << 8) | (privKeyBuf[i + 3]);
        if ((unsigned int)Coeff[1] != (unsigned int)SIGNATURE_REFKEY_ID) {
            goto cleanup;
        }

        ENSURE_OR_GO_CLEANUP((index + 4) < privKeyLen);
        pStoreCtx->keyid = ((unsigned int)privKeyBuf[index] << 24) | ((unsigned int)privKeyBuf[index + 1] << 16) |
                           ((unsigned int)privKeyBuf[index + 2] << 8) | (unsigned int)privKeyBuf[index + 3];
    }
#endif

    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    pStoreCtx->isFile = 0;

    ret = 0;
cleanup:
    return ret;
}

static int sss_handle_rsa_ref_key(sss_provider_store_obj_t *pStoreCtx, EVP_PKEY *pEVPKey)
{
    int ret             = 1;
    sss_status_t status = kStatus_SSS_Fail;
    int openssl_ret     = 0;
    size_t coefficient1 = 0;
    size_t keyid        = 0;

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pEVPKey != NULL);

    openssl_ret = EVP_PKEY_get_size_t_param(pEVPKey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &coefficient1);
    ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

    /* confirm that the key is reference key */
    if (coefficient1 != SIGNATURE_REFKEY_ID) {
        // Not a reference key
        goto cleanup;
    }

    openssl_ret = EVP_PKEY_get_size_t_param(pEVPKey, OSSL_PKEY_PARAM_RSA_FACTOR2, &keyid);
    ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

    pStoreCtx->keyid = keyid;

    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    status = sss_key_object_init(&(pStoreCtx->object), &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_get_handle(&(pStoreCtx->object), pStoreCtx->keyid);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    pStoreCtx->isFile = 0;

    ret = 0;
cleanup:
    return ret;
}

static int sss_file_store_object_load(
    void *ctx, OSSL_CALLBACK *object_cb, void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    int ret                             = 1;
    sss_provider_store_obj_t *pStoreCtx = ctx;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *keytype;
    EVP_PKEY *pEVPKey = NULL;

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pFile != NULL);

    pEVPKey = PEM_read_PrivateKey(pStoreCtx->pFile, NULL, NULL, NULL);
    if (pEVPKey) /* Handle private key */
    {
        pStoreCtx->pEVPPkey     = pEVPKey;
        pStoreCtx->isPrivateKey = true;

        if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_EC) {
            keytype = "EC";
            ret     = sss_handle_ecc_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
            }
        }
        else if (EVP_PKEY_id(pEVPKey) == EVP_PKEY_RSA) {
            keytype = "RSA";
            ret     = sss_handle_rsa_ref_key(pStoreCtx, pEVPKey);
            if (ret != 0) {
                /* Not a ref key */
                sssProv_Print(LOG_FLOW_ON, "Not a ref key \n");
            }
        }
        else {
            goto cleanup;
        }
        goto key_read_complete;
    }

    fseek(pStoreCtx->pFile, 0, SEEK_SET);
    pEVPKey = PEM_read_PUBKEY(pStoreCtx->pFile, NULL, NULL, NULL);
    if (pEVPKey) /* Handle public key */
    {
        pStoreCtx->isPrivateKey = false;
        pStoreCtx->pEVPPkey     = pEVPKey;
        pStoreCtx->isFile       = 1;
        if (EVP_PKEY_RSA == EVP_PKEY_id(pStoreCtx->pEVPPkey)) {
            keytype = "RSA";
        }
        else if (EVP_PKEY_EC == EVP_PKEY_id(pStoreCtx->pEVPPkey)) {
            keytype = "EC";
        }
        else {
            goto cleanup;
        }
    }
    else {
        goto cleanup;
    }

key_read_complete:
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pStoreCtx, sizeof(pStoreCtx));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
cleanup:
    return 1;
}

static int sss_file_store_object_eof(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = ctx;

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pFile != NULL) {
            return 0;
        }
    }
    return 1;
}

static int sss_file_store_object_close(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = ctx;
    if (pStoreCtx != NULL) {
        if (pStoreCtx->pFile != NULL) {
            fclose(pStoreCtx->pFile);
        }
    }
    return 1;
}

const OSSL_DISPATCH sss_file_store_object_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))sss_file_store_object_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))sss_file_store_object_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))sss_file_store_object_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))sss_file_store_object_close},
    {0, NULL}};
