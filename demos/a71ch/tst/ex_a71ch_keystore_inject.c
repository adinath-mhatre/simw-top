/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <stdio.h>
#include <string.h>

#include "ex_a71ch_keystore.h"
#include "sm_apdu.h"
#include "stdlib.h"

static ex_sss_boot_ctx_t gex_sss_a71ch_keystore;

#define CERTIFICATE = {0x00, 0x21};
#define SSCP_PARAMS(p1, p2, p3, p4, p5, p6)                     \
    SSCP_OP_SET_PARAM(/* First param always ContextReference */ \
        kSSCP_ParamType_ContextReference,                       \
        kSSCP_ParamType_##p1,                                   \
        kSSCP_ParamType_##p2,                                   \
        kSSCP_ParamType_##p3,                                   \
        kSSCP_ParamType_##p4,                                   \
        kSSCP_ParamType_##p5,                                   \
        kSSCP_ParamType_##p6)

#define SET_OP_0_KeyObject()              \
    op.params[0].context.ptr = keyObject; \
    op.params[0].context.type = kSSCP_ParamContextType_SSS_Object;

typedef struct
{
    /** Fixed - Unique 32bit magic number.
    *
    * In case some one over-writes we can know. */
    uint32_t magic;
    /** Fixed - constant based on version number */
    uint16_t version;

    uint16_t maxEntries;
    /** Dynamic entries */
    keyIdAndTypeIndexLookup_t entries[KS_N_ENTIRES];
} keyStoreTableEEPROM_t;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_a71ch_keystore)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

static HLSE_RET_CODE a71ch_allocate_handle(sss_a71ch_key_store_t *keyStore,
    uint32_t extKeyId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

static HLSE_RET_CODE a71ch_set_key(keyStoreTable_t *keystore_shadow, uint32_t extId, uint8_t *key, size_t keyLen);

static HLSE_RET_CODE a71ch_savekeystore(sss_a71ch_key_store_t *keyStore);

void getA71CHKeyStore(sss_a71ch_key_store_t **ks, sscp_context_reference_t *ref);

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t extKeyId = COMMON_KEY_ID;
    /*For keystore version 2*/
    sss_key_part_t key_part = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_Certificate;
    /* This example is for Keystore version 2
     * To use for newer versions, update keyPart and cipherType
     */
    uint8_t key[] = {0, 1};
    size_t keyLen = sizeof(key);
    sscp_operation_t op = {0};

    sss_object_t object;
    sss_status = sss_key_object_init(&object, &gex_sss_a71ch_keystore.ks);
    sss_sscp_object_t *keyObject = (sss_sscp_object_t *)&(object);

    op.paramTypes = SSCP_PARAMS(ValueInput, ValueInput, None, None, None, None);
    SET_OP_0_KeyObject();
    sss_a71ch_key_store_t *a71ch_keystore = NULL;
    getA71CHKeyStore(&a71ch_keystore, &op.params[0].context);

    HLSE_RET_CODE hlseret;
    hlseret = a71ch_allocate_handle(a71ch_keystore, extKeyId, key_part, cipherType, keyLen, kKeyObject_Mode_Persistent);
    if (hlseret != HLSE_SW_OK) {
        LOG_E("Allocate handle failed \n");
        sss_status = kStatus_SSS_Fail;
        goto cleanup;
    }

    hlseret = a71ch_set_key(a71ch_keystore->keystore_shadow, extKeyId, key, keyLen);
    if (hlseret != HLSE_SW_OK) {
        LOG_E("set key failed \n");
        sss_status = kStatus_SSS_Fail;
        goto cleanup;
    }
    hlseret = a71ch_savekeystore(a71ch_keystore);
    if (hlseret != HLSE_SW_OK) {
        LOG_E("keystore save failed \n");
        sss_status = kStatus_SSS_Fail;
        goto cleanup;
    }

    LOG_I("Passed\n");
    sss_status = kStatus_SSS_Success;

cleanup:
    return sss_status;
}

static HLSE_RET_CODE a71ch_allocate_handle(sss_a71ch_key_store_t *keyStore,
    uint32_t extKeyId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    HLSE_RET_CODE hlseret = HLSE_SW_OK;
    keyStoreTable_t *keystore_shadow = keyStore->keystore_shadow;
    uint8_t intIndex = 2;
    for (int i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == 0) {
            keyEntry->extKeyId = extKeyId;
            keyEntry->keyIntIndex = intIndex;
            keyEntry->keyPart = (uint8_t)key_part;
            //keyEntry->cipherType = (uint8_t)cipherType;
            break;
        }
    }

    HLSE_OBJECT_INDEX index = intIndex;
    HLSE_OBJECT_TYPE objType = HLSE_CERTIFICATE;
    U16 templateSize = 3;
    HLSE_ATTRIBUTE attr[3];
    HLSE_OBJECT_HANDLE handle = 0;
    void *pMem;
    pMem = malloc(keyByteLenMax);
    if (NULL != pMem) {
        attr[0].type = HLSE_ATTR_OBJECT_TYPE;
        attr[0].value = &objType;
        attr[0].valueLen = sizeof(objType);
        attr[1].type = HLSE_ATTR_OBJECT_INDEX;
        attr[1].value = &index;
        attr[1].valueLen = sizeof(index);
        attr[2].type = HLSE_ATTR_OBJECT_VALUE;
        /* This is dummy value we write... Actually this source code */
        attr[2].value = pMem;
        attr[2].valueLen = (U16)keyByteLenMax;

        memset(pMem, 0, keyByteLenMax);
        hlseret = HLSE_CreateObject(attr, templateSize, &handle);
        if (hlseret == HLSE_OBJ_ALREADY_EXISTS) {
            hlseret = HLSE_SW_OK;
        }
        free(pMem);

        hlseret = a71ch_savekeystore(keyStore);
    }
    return hlseret;
}

static HLSE_RET_CODE a71ch_set_key(keyStoreTable_t *keystore_shadow, uint32_t extId, uint8_t *key, size_t keyLen)
{
    HLSE_RET_CODE resSW = HLSE_ERR_API_ERROR;
    uint16_t intId = 0;
    U8 i = 0;
    HLSE_OBJECT_HANDLE Handles[5];
    HLSE_OBJECT_HANDLE GetHandle = 0;
    U16 HandlesNum = sizeof(Handles) / sizeof(HLSE_OBJECT_HANDLE);
    U16 HandlesNum_copy;
    HLSE_ATTRIBUTE attr;

    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == extId) {
            intId = keyEntry->keyIntIndex;
            break;
        }
    }

    resSW = HLSE_EnumerateObjects(HLSE_CERTIFICATE, Handles, &HandlesNum);
    if (resSW == HLSE_SW_OK) {
        HandlesNum_copy = HandlesNum;
        while (HandlesNum_copy) {
            if (HLSE_GET_OBJECT_INDEX(Handles[i]) == intId) {
                GetHandle = Handles[i];
                break;
            }
            i++;
            HandlesNum_copy--;
        }
    }
    if (GetHandle != 0) {
        attr.type = HLSE_ATTR_OBJECT_VALUE;
        attr.value = key;
        attr.valueLen = (U16)keyLen;
        resSW = HLSE_SetObjectAttribute(GetHandle, &attr);
    }
    return resSW;
}

static HLSE_RET_CODE a71ch_savekeystore(sss_a71ch_key_store_t *keyStore)
{
    HLSE_RET_CODE hlseret;
    if (keyStore->shadow_handle == 0) {
        hlseret = HLSE_ERR_API_ERROR;
    }
    else {
        int argc = gex_sss_argc;
        const char **argv = gex_sss_argv;
        char version = '0';
        size_t ssid_size = 0;
        bool found_version = false;

        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[j], "-keystoreversion") == 0) {
                j++;
                if (j >= argc) {
                    LOG_E("Invalid arguments");
                    return HLSE_ERR_API_ERROR;
                }
                ssid_size = strlen(argv[j]);
                if (ssid_size > 1) {
                    return HLSE_ERR_NOT_SUPPORTED;
                }
                version = *(argv[j]);
                found_version = true;
                break;
            }
        }
        /* This example is for Keystore version 2
         * To use for newer versions, update keyPart and cipherType
         */
        uint16_t keystore_version = 0x0002;
        if (found_version) {
            keystore_version = version - '0';
        }
        LOG_I("keystore version req = %d\n", keystore_version);

        keyStoreTableEEPROM_t eeKeyStore;

        eeKeyStore.magic = keyStore->keystore_shadow->magic;
        eeKeyStore.version = keystore_version;
        eeKeyStore.maxEntries = keyStore->keystore_shadow->maxEntries;
        memcpy(eeKeyStore.entries, keyStore->keystore_shadow->entries, sizeof(eeKeyStore.entries));

        HLSE_ATTRIBUTE attr;
        attr.type = HLSE_ATTR_OBJECT_VALUE;
        attr.value = &eeKeyStore;
        attr.valueLen = sizeof(eeKeyStore);
        /* write gkeystore_shadow_ch */
        hlseret = HLSE_SetObjectAttribute(keyStore->shadow_handle, &attr);
    }
    return hlseret;
}

void getA71CHKeyStore(sss_a71ch_key_store_t **ks, sscp_context_reference_t *ref)
{
    switch (ref->type) {
    case kSSCP_ParamContextType_SSS_Symmetric: {
        sss_sscp_symmetric_t *ctx = (sss_sscp_symmetric_t *)ref->ptr;
        *ks = (sss_a71ch_key_store_t *)ctx->keyObject->keyStore;
    } break;
    case kSSCP_ParamContextType_SSS_Aead:
        break;
    case kSSCP_ParamContextType_SSS_Digest:
        break;
    case kSSCP_ParamContextType_SSS_Mac:
        break;
    case kSSCP_ParamContextType_SSS_Tunnel:
        break;
    case kSSCP_ParamContextType_SSS_DeriveKey: {
        sss_derive_key_t *ctx = (sss_derive_key_t *)ref->ptr;
        *ks = (sss_a71ch_key_store_t *)ctx->keyObject->keyStore;
        break;
    }
    case kSSCP_ParamContextType_SSS_Asymmetric: {
        sss_asymmetric_t *ctx = (sss_asymmetric_t *)ref->ptr;
        *ks = (sss_a71ch_key_store_t *)ctx->keyObject->keyStore;
        break;
    }
    case kSSCP_ParamContextType_SSS_Object: {
        sss_object_t *pobj = (sss_object_t *)ref->ptr;
        *ks = (sss_a71ch_key_store_t *)pobj->keyStore;
        break;
    }
    case kSSCP_ParamContextType_SSS_KeyStore: {
        *ks = (sss_a71ch_key_store_t *)ref->ptr;
        break;
    }
    case kSSCP_ParamContextType_SSS_RandomGen:
        *ks = (sss_a71ch_key_store_t *)ref->ptr;
        break;
    }
}
