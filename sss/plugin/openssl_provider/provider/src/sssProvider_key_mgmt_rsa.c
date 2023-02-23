/**
 * @file sssProvider_key_mgmt_rsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for RSA key management
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_RSA

/* ********************** Include files ********************** */
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include "sssProvider_main.h"

/* ********************** Private funtions ******************* */

static void *sss_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = NULL;
    if (!reference || reference_sz != sizeof(pStoreCtx))
        return NULL;

    pStoreCtx                               = *(sss_provider_store_obj_t **)reference;
    *(sss_provider_store_obj_t **)reference = NULL;
    return pStoreCtx;
}

static void sss_rsa_keymgmt_free(void *keydata)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    OPENSSL_free(keydata);
}

static int sss_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    smStatus_t status                   = SM_NOT_OK;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sss_se05x_session_t *pSession       = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
    OSSL_PARAM *p;
    int ret = 0;

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    if (pStoreCtx->isFile) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        /* EVP_PKEY_size() returns the maximum suitable size for the output buffers
        for almost all operations that can be done with pkey */
        pStoreCtx->maxSize = EVP_PKEY_size(pStoreCtx->pEVPPkey);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, EVP_PKEY_bits(pStoreCtx->pEVPPkey))) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->maxSize)) { /* Signature size */
            goto cleanup;
        }
    }
    else {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
        ENSURE_OR_GO_CLEANUP(pSession != NULL);

        //Get the size of the key
        status = Se05x_API_ReadSize(&(pSession->s_ctx), pStoreCtx->keyid, &(pStoreCtx->key_len));
        if (status != SM_OK) {
            return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, (pStoreCtx->key_len) * 8)) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->key_len)) { /* Signature size */
            goto cleanup;
        }
    }

    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM *sss_rsa_keymgmt_gettable_params(void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    static OSSL_PARAM gettable[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END};

    return gettable;
}

static const char *sss_rsa_keymgmt_query_operation_name(int operation_id)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    return "RSA";
}

static int sss_rsa_keymgmt_has(const void *keydata, int selection)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    int ok                              = 1;

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->isFile) {
        if (pStoreCtx->pEVPPkey == NULL) {
            return 0;
        }

        if (EVP_PKEY_id(pStoreCtx->pEVPPkey) == EVP_PKEY_RSA) {
            if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (ok) : (0);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (0) : (ok);
                return ret;
            }
            else {
                // Any other - return 0.
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
    else {
        if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Pair ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Private) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Public) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
}

const OSSL_DISPATCH sss_rsa_keymgmt_dispatch[] = {{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sss_rsa_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sss_rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sss_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sss_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))sss_rsa_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sss_rsa_keymgmt_has},
    {0, NULL}};

#endif //#if SSS_HAVE_RSA
