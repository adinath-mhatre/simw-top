/**
 * @file sssProvider_ecdh.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for ECDH using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ECC

/* ********************** Include files ********************** */
#include <string.h>
#include "sssProvider_main.h"

/* ********************** structure definition *************** */
typedef struct
{
    EVP_PKEY *pPeerEVPPkey;
    sss_provider_store_obj_t *pStoreObjCtx; // Host key object
    sss_provider_context_t *pProvCtx;
} sss_provider_ecdh_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_ecdh_keyexch_newctx(void *provctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_ecdh_ctx_st *pEcdhCtx = OPENSSL_zalloc(sizeof(sss_provider_ecdh_ctx_st));
    if (pEcdhCtx != NULL) {
        pEcdhCtx->pProvCtx = provctx;
    }
    return pEcdhCtx;
}

static void sss_ecdh_keyexch_freectx(void *ctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    if (pEcdhctx != NULL) {
        OPENSSL_clear_free(pEcdhctx, sizeof(sss_provider_ecdh_ctx_st));
    }
    return;
}

static int sss_ecdh_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    int ret                             = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pStoreObjCtx = pStoreCtx;
    ret                    = 1;
cleanup:
    return ret;
}

static int sss_ecdh_keyexch_set_peer(void *ctx, void *provkey)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    int ret                             = 0;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pPeerEVPPkey = pStoreCtx->pEVPPkey;
    ret                    = 1;
cleanup:
    return ret;
}

static int sss_ecdh_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    int ret                            = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    sss_se05x_session_t *pSession      = NULL;
    EVP_PKEY_CTX *evpCtx               = NULL;

    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(secretlen != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pPeerEVPPkey != NULL);

    if (pEcdhctx->pStoreObjCtx->keyid != 0) {
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx->session);
        ENSURE_OR_GO_CLEANUP(pSession != NULL);

        if (secret == NULL) {
            *secretlen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
            return (*secretlen > 0);
        }
        else {
            smStatus_t status;
            uint8_t pubBuf[256] = {
                0,
            };
            size_t pubBufLen         = 0;
            unsigned char *pubKeyPtr = pubBuf;
            pubBufLen                = i2d_PublicKey(pEcdhctx->pPeerEVPPkey, &pubKeyPtr);
            ENSURE_OR_GO_CLEANUP(pubBufLen > 0);

            sssProv_Print(LOG_FLOW_ON, "Performing ECDH on SE05x \n");

            status = Se05x_API_ECDHGenerateSharedSecret(
                &(pSession->s_ctx), pEcdhctx->pStoreObjCtx->keyid, pubBuf, pubBufLen, secret, secretlen);
            ENSURE_OR_GO_CLEANUP(status == SM_OK);
        }
    }
    else {
        if (secret == NULL) {
            *secretlen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
            return (*secretlen > 0);
        }
        else {
            int openssl_ret   = 0;
            size_t secret_len = outlen;

            ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx->pEVPPkey != NULL);

            sssProv_Print(LOG_FLOW_ON, "Not a key in secure element. Performing ECDH on host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdhctx->pStoreObjCtx->pEVPPkey, NULL);
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            EVP_PKEY_derive_init(evpCtx);

            openssl_ret = EVP_PKEY_derive_set_peer(evpCtx, pEcdhctx->pPeerEVPPkey);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_derive(evpCtx, secret, &secret_len);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            *secretlen = secret_len;
        }
    }

    ret = 1;
cleanup:
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

const OSSL_DISPATCH sss_ecdh_keyexch_functions[] = {{OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sss_ecdh_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sss_ecdh_keyexch_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))sss_ecdh_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sss_ecdh_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sss_ecdh_keyexch_freectx},
    {0, NULL}};

#endif //#if SSS_HAVE_ECC
