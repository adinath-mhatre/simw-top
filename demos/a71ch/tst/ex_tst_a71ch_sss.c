/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <a71ch_api.h>
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_util_asn1_der.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EC_KEY_BIT_LEN 256

#ifndef MAKE_LOOP_TEST_ID
#define MAKE_LOOP_TEST_ID(ID, INDEX) (0xEF000000u + ID + INDEX)
#endif /* MAKE_LOOP_TEST_ID */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* clang-format off */
const uint8_t keyPairData[] = { 0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x78, 0xE5, 0x20, 0x6A,
    0x08, 0xED, 0xD2, 0x52, 0x36, 0x33, 0x8A, 0x24,
    0x84, 0xE4, 0x2F, 0x1F, 0x7D, 0x1F, 0x6D, 0x94,
    0x37, 0xA9, 0x95, 0x86, 0xDA, 0xFC, 0xD2, 0x23,
    0x6F, 0xA2, 0x87, 0x35, 0xA1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9, 0x20,
    0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7, 0x20,
    0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86, 0xD2,
    0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A, 0x15,
    0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78, 0x63,
    0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D, 0x87,
    0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76, 0x63,
    0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31, 0x8E,
    0x68, 0x7C };

const uint8_t extPubKeyData[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xED, 0xA7, 0xE9, 0x0B, 0xF9,
    0x20, 0xCF, 0xFB, 0x9D, 0xF6, 0xDB, 0xCE, 0xF7,
    0x20, 0xE1, 0x23, 0x8B, 0x3C, 0xEE, 0x84, 0x86,
    0xD2, 0x50, 0xE4, 0xDF, 0x30, 0x11, 0x50, 0x1A,
    0x15, 0x08, 0xA6, 0x2E, 0xD7, 0x49, 0x52, 0x78,
    0x63, 0x6E, 0x61, 0xE8, 0x5F, 0xED, 0xB0, 0x6D,
    0x87, 0x92, 0x0A, 0x04, 0x19, 0x14, 0xFE, 0x76,
    0x63, 0x55, 0xDF, 0xBD, 0x68, 0x61, 0x59, 0x31,
    0x8E, 0x68, 0x7C
};

/* clang-format on */

static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

#include "a71ch_util.h"
#include "sm_types.h"
#include "tst_sm_util.h"

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;
    uint8_t digest[32] = "Hello World";
    size_t digestLen;
    uint8_t signature[256] = {0};
    size_t signatureLen;
    sss_object_t keyPair[4];
    uint32_t keyPairObjectKeyId[4];
    sss_object_t keyPairTest;
    uint32_t keyPairTestObjectKeyId;
    sss_object_t key_pub;
    sss_asymmetric_t ctx_asymm = {0};
    sss_asymmetric_t ctx_verify = {0};

    // Variables used by calls to legacy API
    U16 sw = 0;

    LOG_I(
        "Running Mixed SSS/A71CH Host API Elliptic Curve Cryptography Example "
        "ex_tst_a71ch_sss.c");
    digestLen = sizeof(digest);

    /* doc:start ex_sss_asymmetric-allocate-key */
    /* Pre-requisite for Signing Part*/
    status = sss_key_object_init(&keyPair[0], &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    keyPairObjectKeyId[0] = MAKE_TEST_ID(__LINE__);
    status = sss_key_object_allocate_handle(&keyPair[0],
        keyPairObjectKeyId[0],
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(keyPairData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks, &keyPair[0], keyPairData, sizeof(keyPairData), EC_KEY_BIT_LEN, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    /* doc:end ex_sss_asymmetric-allocate-key */

    // Create additional keys
    for (unsigned int i = 1u; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        LOG_I("Creating additional keypair");
        status = sss_key_object_init(&keyPair[i], &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        keyPairObjectKeyId[i] = MAKE_LOOP_TEST_ID(__LINE__, i);
        status = sss_key_object_allocate_handle(&keyPair[i],
            keyPairObjectKeyId[i],
            kSSS_KeyPart_Pair,
            kSSS_CipherType_EC_NIST_P,
            sizeof(keyPairData),
            kKeyObject_Mode_Persistent);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_store_generate_key(&pCtx->ks, &keyPair[i], EC_KEY_BIT_LEN, NULL);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    sss_key_store_save(&pCtx->ks);

    /* doc:start ex_sss_asymmetric-asym-sign */
    status =
        sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair[0], kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    signatureLen = sizeof(signature);
    /* Do Signing */
    LOG_I("Do Signing");
    LOG_MAU8_I("digest", digest, digestLen);
    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("signature", signature, signatureLen);
    LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);
    /* doc:end ex_sss_asymmetric-asym-sign */

    /* Pre requiste for Verifying Part*/
    status = sss_key_object_init(&key_pub, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&key_pub,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        kSSS_CipherType_EC_NIST_P,
        sizeof(extPubKeyData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(&pCtx->ks, &key_pub, extPubKeyData, sizeof(extPubKeyData), EC_KEY_BIT_LEN, NULL, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* doc:start ex_sss_asymmetric-asym-verify */
    status =
        sss_asymmetric_context_init(&ctx_verify, &pCtx->session, &key_pub, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Do Verify");
    LOG_MAU8_I("digest", digest, digestLen);
    LOG_MAU8_I("signature", signature, signatureLen);
    status = sss_asymmetric_verify_digest(&ctx_verify, digest, digestLen, signature, signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Verification Successful !!!");
    /* doc:end ex_sss_asymmetric-asym-verify */

    /* Access the A71CH with the (legacy) Host API */
    SST_Index_t keyIdx = ((sss_sscp_object_t *)&keyPair[0])->slotId;
    U8 pubEccKeyScratch[4][128];
    U16 pubEccKeyScratchLen[4] = {0};

    LOG_I("A71_GetPublicKeyEccKeyPair(0x%02x)", keyIdx);
    pubEccKeyScratchLen[0] = sizeof(pubEccKeyScratch);
    sw = A71_GetPublicKeyEccKeyPair(keyIdx, pubEccKeyScratch[0], &pubEccKeyScratchLen[0]);
    status = ((sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail);
    ENSURE_OR_GO_CLEANUP(sw == SW_OK);
    LOG_MAU8_I("Pub Key from pair", pubEccKeyScratch[0], pubEccKeyScratchLen[0]);

    // Read out additional keys
    for (unsigned int i = 1u; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        keyIdx = ((sss_sscp_object_t *)&keyPair[i])->slotId;
        LOG_I(
            "Reading out public key of keypair with Legacy API (iter=%d at "
            "index=%d)",
            i,
            keyIdx);
        pubEccKeyScratchLen[i] = sizeof(pubEccKeyScratch[i]);
        sw = A71_GetPublicKeyEccKeyPair(keyIdx, pubEccKeyScratch[i], &pubEccKeyScratchLen[i]);
        status = ((sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail);
        ENSURE_OR_GO_CLEANUP(sw == SW_OK);
        LOG_MAU8_I("Pub Key from pair", pubEccKeyScratch[i], pubEccKeyScratchLen[i]);
    }

    uint8_t pubEccKeyScratchSss[4][128];
    size_t pubEccKeyScratchSssSize[4] = {sizeof(pubEccKeyScratchSss)};
    size_t pubEccKeyScratchSssBitlen[4] = {EC_KEY_BIT_LEN};

    // Read out public keys with sss api. Start from objectID
    for (unsigned int i = 0; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        sss_object_t key_pair_tmp;

        LOG_I(
            "Reading out public key of keypair with SSS API (iter=%d at "
            "objectId=0x%08X)",
            i,
            keyPairObjectKeyId[i]);
        status = sss_key_object_init(&key_pair_tmp, &pCtx->ks);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = sss_key_object_get_handle(&key_pair_tmp, keyPairObjectKeyId[i]);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        pubEccKeyScratchSssSize[i] = sizeof(pubEccKeyScratchSss);
        status = sss_key_store_get_key(&pCtx->ks,
            &key_pair_tmp,
            pubEccKeyScratchSss[i],
            &pubEccKeyScratchSssSize[i],
            &pubEccKeyScratchSssBitlen[i]);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        LOG_MAU8_I("Pub Key from pair", pubEccKeyScratchSss[i], pubEccKeyScratchSssSize[i]);
    }

    // Compare whether the same public key value has been retrieved
    for (unsigned int i = 0; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        uint16_t publicKeyIndex = 0;
        size_t publicKeyLen = 0;
        int result;

        LOG_I(
            "Check whether the same public key value has been retrieved "
            "(iter=%d)",
            i);

        // Get raw data from pubEccKeyScratchSss
        status = sss_util_pkcs8_asn1_get_ec_public_key_index(
            pubEccKeyScratchSss[i], pubEccKeyScratchSssSize[i], &publicKeyIndex, &publicKeyLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        // LOG_MAU8_I("Raw Pub Key from pair", &pubEccKeyScratchSss[i][publicKeyIndex], (U16)publicKeyLen);

        result = AX_COMPARE_BYTE_ARRAY("pubEccKeyScratch[i]",
            pubEccKeyScratch[i],
            pubEccKeyScratchLen[i],
            "pubEccKeyScratchSss",
            &pubEccKeyScratchSss[i][publicKeyIndex],
            (U16)publicKeyLen,
            AX_COLON_32);
        status = ((result == 1) ? kStatus_SSS_Success : kStatus_SSS_Fail);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }

    LOG_I("Try to create one public keypair too much: Must fail (negative test)");
    status = sss_key_object_init(&keyPairTest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    keyPairTestObjectKeyId = MAKE_TEST_ID(__LINE__);
    status = sss_key_object_allocate_handle(&keyPairTest,
        keyPairTestObjectKeyId,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(keyPairData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Fail);

    LOG_I("Now delete the first keypair object created");
    status = sss_key_object_get_handle(&keyPairTest, keyPairObjectKeyId[0]);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_erase_key(&pCtx->ks, &keyPairTest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Now read out the value just deleted (must fail)");
    pubEccKeyScratchSssSize[0] = sizeof(pubEccKeyScratchSss);
    status = sss_key_store_get_key(
        &pCtx->ks, &keyPairTest, pubEccKeyScratchSss[0], &pubEccKeyScratchSssSize[0], &pubEccKeyScratchSssBitlen[0]);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Fail);

    LOG_I("Generate a new keypair");
    status = sss_key_object_init(&keyPairTest, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    keyPairObjectKeyId[0] = MAKE_TEST_ID(__LINE__);
    status = sss_key_object_allocate_handle(&keyPair[0],
        keyPairObjectKeyId[0],
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        sizeof(keyPairData),
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair[0], EC_KEY_BIT_LEN, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Read out public keys of keypairs with legacy API
    for (unsigned int i = 0; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        keyIdx = ((sss_sscp_object_t *)&keyPair[i])->slotId;
        LOG_I(
            "Reading out public key of keypair with Legacy API (iter=%d at "
            "index=%d)",
            i,
            keyIdx);
        pubEccKeyScratchLen[i] = sizeof(pubEccKeyScratch[i]);
        sw = A71_GetPublicKeyEccKeyPair(keyIdx, pubEccKeyScratch[i], &pubEccKeyScratchLen[i]);
        status = ((sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail);
        ENSURE_OR_GO_CLEANUP(sw == SW_OK);
        LOG_MAU8_I("Pub Key from pair", pubEccKeyScratch[i], pubEccKeyScratchLen[i]);
    }

    LOG_I("Reading out public key of keypair with SSS API (objectId=0x%08X)", keyPairObjectKeyId[0]);
    pubEccKeyScratchSssSize[0] = sizeof(pubEccKeyScratchSss);
    status = sss_key_store_get_key(
        &pCtx->ks, &keyPair[0], pubEccKeyScratchSss[0], &pubEccKeyScratchSssSize[0], &pubEccKeyScratchSssBitlen[0]);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // Provoke failure
    // pubEccKeyScratch[3][0] ^= 0xFF;

    // Compare once again the scratch arrays (same public key value has been retrieved)
    for (unsigned int i = 0; i < sizeof(keyPair) / sizeof(sss_object_t); i++) {
        uint16_t publicKeyIndex = 0;
        size_t publicKeyLen = 0;
        int result;

        LOG_I(
            "Check whether the same public key value has been retrieved "
            "(iter=%d)",
            i);

        // Get raw data from pubEccKeyScratchSss
        status = sss_util_pkcs8_asn1_get_ec_public_key_index(
            pubEccKeyScratchSss[i], pubEccKeyScratchSssSize[i], &publicKeyIndex, &publicKeyLen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        // LOG_MAU8_I("Raw Pub Key from pair", &pubEccKeyScratchSss[i][publicKeyIndex], (U16)publicKeyLen);

        result = AX_COMPARE_BYTE_ARRAY("pubEccKeyScratch[i]",
            pubEccKeyScratch[i],
            pubEccKeyScratchLen[i],
            "pubEccKeyScratchSss",
            &pubEccKeyScratchSss[i][publicKeyIndex],
            (U16)publicKeyLen,
            AX_COLON_32);
        status = ((result == 1) ? kStatus_SSS_Success : kStatus_SSS_Fail);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_tst_a71ch_sss Example Success !!!...");
    }
    else {
        LOG_E("ex_tst_a71ch_sss Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL) {
        sss_asymmetric_context_free(&ctx_asymm);
    }
    if (ctx_verify.session != NULL) {
        sss_asymmetric_context_free(&ctx_verify);
    }
    return status;
}
