/*
 * Copyright 2016 The Android Open Source Project
 * Copyright 2019 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <hardware/keymaster1.h>
#define LOG_TAG "NXPKeymasterDevice"
#include <cutils/log.h>

#include "attestation_record.h"
#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_context.h>
#include <keymaster/soft_keymaster_context.h>
#include <keymaster/soft_keymaster_logger.h>

#include "openssl_utils.h"

#include "openssl_err.h"

#include "nxEnsure.h"
#include <fsl_sss_util_asn1_der.h>
#include <keymaster/se050_keymaster_attestation_record.h>
#include <keymaster/se050_keymaster_certificate_chain.h>

namespace keymaster {

#define ASN1_SKIP_TO_NEXT_TAG(pTLV, taglen)                                                        \
    {                                                                                              \
        if (taglen < 0x7F) {                                                                       \
            pTLV += taglen + 1 + 1 /* Length byte */;                                              \
        } else if (taglen < 0xFF) {                                                                \
            pTLV += taglen + 1 + 2 /* Length bytes */;                                             \
        } else {                                                                                   \
            pTLV += taglen + 1 + 3 /* Length bytes */;                                             \
        }                                                                                          \
    }

static int check_tag(int tag) {
    int ret = 0;
    switch (tag) {
    case ASN_TAG_INT:
    case ASN_TAG_SEQUENCE:
    case ASN_TAG_BITSTRING:
    case ASN_TAG_OBJ_IDF:
    case ASN_TAG_OCTETSTRING:
        break;
    default:
        LOG_E("Wrong Tag parsed -- %d \n", tag);
        ret = 1;
        break;
    }
    return ret;
}

int asn_1_parse_tlv(uint8_t* pbuf, size_t* taglen, size_t* bufindex) {
    size_t Len;
    uint8_t* buf = pbuf + *bufindex;
    int tag;
    tag = *buf++; /*Exclude The Tag*/
    Len = *buf++;
    int ret = 0;
    if (check_tag(tag)) {
        ret = 1;
        goto exit;
    }
    if (Len <= 0x7FU) {
        *taglen = Len;
        *bufindex += 1 + 1;
        goto exit;
    } else if (Len == 0x81) {
        *taglen = *buf++;
        *bufindex += 1 + 2;
        goto exit;
    } else if (Len == 0x82) {
        *taglen = *buf++;
        *taglen = (*taglen << 8) | (*buf++);
        *bufindex += 1 + 3;
        goto exit;
    }
    ret = 1;
exit:
    return ret;
}

#define ASN1_INTEGER_SET STACK_OF(ASN1_INTEGER)
constexpr int kDigitalSignatureKeyUsageBit = 0;
constexpr int kKeyEnciphermentKeyUsageBit = 2;
constexpr int kDataEnciphermentKeyUsageBit = 3;
constexpr int kMaxKeyUsageBit = 8;
constexpr uint kCurrentKeymasterVersion = 3;
constexpr uint kCurrentAttestationVersion = 2;

struct stack_st_ASN1_TYPE_Delete {
    void operator()(stack_st_ASN1_TYPE* p) { sk_ASN1_TYPE_free(p); }
};

struct ASN1_STRING_Delete {
    void operator()(ASN1_STRING* p) { ASN1_STRING_free(p); }
};

struct ASN1_TYPE_Delete {
    void operator()(ASN1_TYPE* p) { ASN1_TYPE_free(p); }
};

#define ASN1_INTEGER_SET STACK_OF(ASN1_INTEGER)

typedef struct km_root_of_trust {
    ASN1_OCTET_STRING* verified_boot_key;
    ASN1_BOOLEAN* device_locked;
    ASN1_ENUMERATED* verified_boot_state;
} KM_ROOT_OF_TRUST;

ASN1_SEQUENCE(KM_ROOT_OF_TRUST) = {
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, verified_boot_key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, device_locked, ASN1_BOOLEAN),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, verified_boot_state, ASN1_ENUMERATED),
} ASN1_SEQUENCE_END(KM_ROOT_OF_TRUST);
IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST);

typedef struct km_auth_list {
    ASN1_INTEGER_SET* purpose;
    ASN1_INTEGER* algorithm;
    ASN1_INTEGER* key_size;
    ASN1_INTEGER_SET* digest;
    ASN1_INTEGER_SET* padding;
    ASN1_INTEGER_SET* kdf;
    ASN1_INTEGER* ec_curve;
    ASN1_INTEGER* rsa_public_exponent;
    ASN1_INTEGER* active_date_time;
    ASN1_INTEGER* origination_expire_date_time;
    ASN1_INTEGER* usage_expire_date_time;
    ASN1_NULL* no_auth_required;
    ASN1_INTEGER* user_auth_type;
    ASN1_INTEGER* auth_timeout;
    ASN1_NULL* allow_while_on_body;
    ASN1_NULL* all_applications;
    ASN1_OCTET_STRING* application_id;
    ASN1_INTEGER* creation_date_time;
    ASN1_INTEGER* origin;
    ASN1_NULL* rollback_resistant;
    KM_ROOT_OF_TRUST* root_of_trust;
    ASN1_INTEGER* os_version;
    ASN1_INTEGER* os_patchlevel;
    ASN1_OCTET_STRING* attestation_application_id;
    ASN1_OCTET_STRING* attestation_id_brand;
    ASN1_OCTET_STRING* attestation_id_device;
    ASN1_OCTET_STRING* attestation_id_product;
    ASN1_OCTET_STRING* attestation_id_serial;
    ASN1_OCTET_STRING* attestation_id_imei;
    ASN1_OCTET_STRING* attestation_id_meid;
    ASN1_OCTET_STRING* attestation_id_manufacturer;
    ASN1_OCTET_STRING* attestation_id_model;
} KM_AUTH_LIST;

ASN1_SEQUENCE(KM_AUTH_LIST) = {
    ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, purpose, ASN1_INTEGER, TAG_PURPOSE.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, algorithm, ASN1_INTEGER, TAG_ALGORITHM.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, key_size, ASN1_INTEGER, TAG_KEY_SIZE.masked_tag()),
    ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, digest, ASN1_INTEGER, TAG_DIGEST.masked_tag()),
    ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, padding, ASN1_INTEGER, TAG_PADDING.masked_tag()),
    ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, kdf, ASN1_INTEGER, TAG_KDF.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, ec_curve, ASN1_INTEGER, TAG_EC_CURVE.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, rsa_public_exponent, ASN1_INTEGER,
                 TAG_RSA_PUBLIC_EXPONENT.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, active_date_time, ASN1_INTEGER, TAG_ACTIVE_DATETIME.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, origination_expire_date_time, ASN1_INTEGER,
                 TAG_ORIGINATION_EXPIRE_DATETIME.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, usage_expire_date_time, ASN1_INTEGER,
                 TAG_USAGE_EXPIRE_DATETIME.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, no_auth_required, ASN1_NULL, TAG_NO_AUTH_REQUIRED.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, user_auth_type, ASN1_INTEGER, TAG_USER_AUTH_TYPE.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, auth_timeout, ASN1_INTEGER, TAG_AUTH_TIMEOUT.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, allow_while_on_body, ASN1_NULL,
                 TAG_ALLOW_WHILE_ON_BODY.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, all_applications, ASN1_NULL, TAG_ALL_APPLICATIONS.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, application_id, ASN1_OCTET_STRING, TAG_APPLICATION_ID.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, creation_date_time, ASN1_INTEGER,
                 TAG_CREATION_DATETIME.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, origin, ASN1_INTEGER, TAG_ORIGIN.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, rollback_resistant, ASN1_NULL, TAG_ROLLBACK_RESISTANT.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, root_of_trust, KM_ROOT_OF_TRUST, TAG_ROOT_OF_TRUST.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, os_version, ASN1_INTEGER, TAG_OS_VERSION.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, os_patchlevel, ASN1_INTEGER, TAG_OS_PATCHLEVEL.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_application_id, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_APPLICATION_ID.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_brand, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_BRAND.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_device, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_DEVICE.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_product, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_PRODUCT.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_serial, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_SERIAL.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_imei, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_IMEI.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_meid, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_MEID.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_manufacturer, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_MANUFACTURER.masked_tag()),
    ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_model, ASN1_OCTET_STRING,
                 TAG_ATTESTATION_ID_MODEL.masked_tag()),
} ASN1_SEQUENCE_END(KM_AUTH_LIST);
IMPLEMENT_ASN1_FUNCTIONS(KM_AUTH_LIST);

typedef struct km_key_description {
    ASN1_INTEGER* attestation_version;
    ASN1_ENUMERATED* attestation_security_level;
    ASN1_INTEGER* keymaster_version;
    ASN1_ENUMERATED* keymaster_security_level;
    ASN1_OCTET_STRING* attestation_challenge;
    KM_AUTH_LIST* software_enforced;
    KM_AUTH_LIST* tee_enforced;
    ASN1_INTEGER* unique_id;
} KM_KEY_DESCRIPTION;

ASN1_SEQUENCE(KM_KEY_DESCRIPTION) = {
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_version, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_security_level, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, keymaster_version, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, keymaster_security_level, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_challenge, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, unique_id, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, software_enforced, KM_AUTH_LIST),
    ASN1_SIMPLE(KM_KEY_DESCRIPTION, tee_enforced, KM_AUTH_LIST),
} ASN1_SEQUENCE_END(KM_KEY_DESCRIPTION);
IMPLEMENT_ASN1_FUNCTIONS(KM_KEY_DESCRIPTION);

static const keymaster_tag_t kDeviceAttestationTags[] = {
    KM_TAG_ATTESTATION_ID_BRAND,        KM_TAG_ATTESTATION_ID_DEVICE, KM_TAG_ATTESTATION_ID_PRODUCT,
    KM_TAG_ATTESTATION_ID_SERIAL,       KM_TAG_ATTESTATION_ID_IMEI,   KM_TAG_ATTESTATION_ID_MEID,
    KM_TAG_ATTESTATION_ID_MANUFACTURER, KM_TAG_ATTESTATION_ID_MODEL,
};

struct KM_AUTH_LIST_Delete {
    void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

struct KM_KEY_DESCRIPTION_Delete {
    void operator()(KM_KEY_DESCRIPTION* p) { KM_KEY_DESCRIPTION_free(p); }
};

static uint32_t get_uint32_value(const keymaster_key_param_t& param) {
    switch (keymaster_tag_get_type(param.tag)) {
    case KM_ENUM:
    case KM_ENUM_REP:
        return param.enumerated;
    case KM_UINT:
    case KM_UINT_REP:
        return param.integer;
    default:
        assert(false);
        return 0xFFFFFFFF;
    }
}

// Insert value in either the dest_integer or the dest_integer_set, whichever is provided.
static keymaster_error_t insert_integer(ASN1_INTEGER* value, ASN1_INTEGER** dest_integer,
                                        ASN1_INTEGER_SET** dest_integer_set) {
    ENSURE_OR_GO_EXIT((dest_integer == nullptr) ^ (dest_integer_set == nullptr));
    ENSURE_OR_GO_EXIT(value);

    if (dest_integer_set) {
        if (!*dest_integer_set)
            *dest_integer_set = sk_ASN1_INTEGER_new_null();
        if (!*dest_integer_set)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        if (!sk_ASN1_INTEGER_push(*dest_integer_set, value))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return KM_ERROR_OK;

    } else if (dest_integer) {
        if (*dest_integer)
            ASN1_INTEGER_free(*dest_integer);
        *dest_integer = value;
        return KM_ERROR_OK;
    }

    assert(false);  // Should never get here.
    return KM_ERROR_OK;

exit:
    return KM_ERROR_UNEXPECTED_NULL_POINTER;
}

static bool allocate_cert_chain(size_t entry_count, keymaster_cert_chain_t* chain,
                                keymaster_error_t* error) {
    ALOGI("%s function called", __FUNCTION__);
    ALOGI("chain->entry_count = %zu", chain->entry_count);
    if (chain->entries) {
        ALOGI("chain->entries present");
        for (size_t i = 0; i < chain->entry_count; ++i)
            delete[] chain->entries[i].data;
        ALOGI("chain->entries[i] deleted");
        delete[] chain->entries;
    }
    ALOGI("Random log");

    chain->entry_count = entry_count;
    chain->entries = new (std::nothrow) keymaster_blob_t[entry_count];
    if (!chain->entries) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }
    ALOGI("Returning from %s", __FUNCTION__);
    return true;
}

keymaster_error_t get_certificate_blob(X509* certificate, keymaster_blob_t* blob) {
    ALOGI("%s called", __FUNCTION__);
    int len = i2d_X509(certificate, nullptr);
    if (len < 0)
        return TranslateLastOpenSslError();

    uint8_t* data = new (std::nothrow) uint8_t[len];
    if (!data)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* p = data;
    i2d_X509(certificate, &p);

    /*
     *  certificate will be of the following format
     *  30 ZZ
     *      30 XX
     *          TBS bytes
     *      30 XX
     *          algorithm
     *      03 YY
     *          signature
     */

    uint8_t* pTLV = data;
    if (*pTLV != 0x30) {
        ALOGE("Certificate parsing failed: Invalid tag");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    size_t tagLen = 0, bufindex = 0;
    int ret = asn_1_parse_tlv(pTLV, &tagLen, &bufindex);
    if (ret != 0) {
        ALOGE("Certificate parsing failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    pTLV = pTLV + bufindex;
    if (*pTLV != 0x30) {
        ALOGE("Certificate parsing failed: Invalid tbs tag");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    bufindex = 0;

    ret = asn_1_parse_tlv(pTLV, &tagLen, &bufindex);
    if (ret != 0) {
        ALOGE("Certificate parsing failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (*pTLV != 0x30) {
        ALOGE("Certificate parsing failed: Invalid algorithm tag");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    bufindex = 0;

    ASN1_SKIP_TO_NEXT_TAG(pTLV, tagLen)
    ret = asn_1_parse_tlv(pTLV, &tagLen, &bufindex);
    if (ret != 0) {
        ALOGE("Certificate parsing failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    bufindex = 0;

    ASN1_SKIP_TO_NEXT_TAG(pTLV, tagLen)
    if (*pTLV != 0x03) {
        ALOGE("Certificate parsing failed: Invalid signature tag");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    ret = asn_1_parse_tlv(pTLV, &tagLen, &bufindex);
    if (ret != 0) {
        ALOGE("Certificate parsing failed");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    /* Set first byte of bitstring as 0x00
     * (Don't skip any bits)
     */

    pTLV = pTLV + bufindex;
    *pTLV = 0x00;

    blob->data_length = len;
    blob->data = data;

    ALOGI("Returning from %s", __FUNCTION__);
    return KM_ERROR_OK;
}

keymaster_error_t add_key_usage_extension(const AuthorizationSet& tee_enforced,
                                          const AuthorizationSet& sw_enforced, X509* certificate) {
    // Build BIT_STRING with correct contents.
    ASN1_BIT_STRING_Ptr key_usage(ASN1_BIT_STRING_new());

    for (size_t i = 0; i <= kMaxKeyUsageBit; ++i) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), i, 0)) {
            return TranslateLastOpenSslError();
        }
    }

    if (tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_SIGN) ||
        tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_VERIFY) ||
        sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_SIGN) ||
        sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_VERIFY)) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kDigitalSignatureKeyUsageBit, 1)) {
            return TranslateLastOpenSslError();
        }
    }

    if (tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_ENCRYPT) ||
        tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_DECRYPT) ||
        sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_ENCRYPT) ||
        sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_DECRYPT)) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kKeyEnciphermentKeyUsageBit, 1) ||
            !ASN1_BIT_STRING_set_bit(key_usage.get(), kDataEnciphermentKeyUsageBit, 1)) {
            return TranslateLastOpenSslError();
        }
    }

    // Convert to octets
    int len = i2d_ASN1_BIT_STRING(key_usage.get(), nullptr);
    if (len < 0) {
        return TranslateLastOpenSslError();
    }
    UniquePtr<uint8_t[]> asn1_key_usage(new (std::nothrow) uint8_t[len]);
    if (!asn1_key_usage.get()) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    uint8_t* p = asn1_key_usage.get();
    len = i2d_ASN1_BIT_STRING(key_usage.get(), &p);
    if (len < 0) {
        return TranslateLastOpenSslError();
    }

    // Build OCTET_STRING
    ASN1_OCTET_STRING_Ptr key_usage_str(ASN1_OCTET_STRING_new());
    if (!key_usage_str.get() ||
        !ASN1_OCTET_STRING_set(key_usage_str.get(), asn1_key_usage.get(), len)) {
        return TranslateLastOpenSslError();
    }

    X509_EXTENSION_Ptr key_usage_extension(X509_EXTENSION_create_by_NID(nullptr,        //
                                                                        NID_key_usage,  //
                                                                        false /* critical */,
                                                                        key_usage_str.get()));
    if (!key_usage_extension.get()) {
        return TranslateLastOpenSslError();
    }

    if (!X509_add_ext(certificate, key_usage_extension.get() /* Don't release; copied */,
                      -1 /* insert at end */)) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

keymaster_cert_chain_t* CreateAttestationChain(keymaster_algorithm_t algorithm,
                                               uint8_t* root_ca_cert, size_t root_ca_cert_size,
                                               keymaster_error_t* error) {
    // If we have to bail it will be because of an allocation failure.
    *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;

    UniquePtr<keymaster_cert_chain_t, CertificateChainDelete> chain(new keymaster_cert_chain_t);
    if (!chain.get())
        return nullptr;
    memset(chain.get(), 0, sizeof(keymaster_cert_chain_t));

    chain->entries = new keymaster_blob_t[4];
    if (!chain->entries)
        return nullptr;

    size_t chain_size = sizeof(chain->entries[0]) * 4;
    memset(chain->entries, 0, chain_size);
    chain->entry_count = 4;

    size_t entry = 0;
    uint8_t signing_cert[4096] = {0};
    if (sizeof(signing_cert) < root_ca_cert_size) {
        return nullptr;
    }
    memcpy(signing_cert, root_ca_cert, root_ca_cert_size);
    uint8_t rsaRootCA[] = RootCAvR406;
    uint8_t rsaInterCA1[] = Intermediate_4LayerCAvR406;
    uint8_t rsaInterCA2[] = CloudConn_Intermediate_040050010004A1F4_RSA;
    uint8_t ecRootCA[] = RootCAvE305;
    uint8_t ecInterCA1[] = Intermediate_4LayerCAvE205;
    uint8_t ecInterCA2[] = CloudConn_Intermediate_040050010004A1F4_ECC;

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        chain->entries[entry].data = dup_array(signing_cert);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = root_ca_cert_size;
        entry++;
        chain->entries[entry].data = dup_array(rsaInterCA2);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(rsaInterCA2);
        entry++;
        chain->entries[entry].data = dup_array(rsaInterCA1);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(rsaInterCA1);
        entry++;
        chain->entries[entry].data = dup_array(rsaRootCA);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(rsaRootCA);
        entry++;
        break;

    case KM_ALGORITHM_EC:
        chain->entries[entry].data = dup_array(signing_cert);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = root_ca_cert_size;
        entry++;
        chain->entries[entry].data = dup_array(ecInterCA2);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(ecInterCA2);
        entry++;
        chain->entries[entry].data = dup_array(ecInterCA1);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(ecInterCA1);
        entry++;
        chain->entries[entry].data = dup_array(ecRootCA);
        if (!chain->entries[entry].data)
            return nullptr;
        chain->entries[entry].data_length = array_length(ecRootCA);
        entry++;
        break;

    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return nullptr;
    };

    assert(entry == 4);

    *error = KM_ERROR_OK;
    return chain.release();
}

bool copy_attestation_chain(keymaster_algorithm_t sign_algorithm, uint8_t* root_ca_cert,
                            size_t root_ca_cert_size, keymaster_cert_chain_t* chain,
                            keymaster_error_t* error) {
    ALOGI("%s called", __FUNCTION__);
    UniquePtr<keymaster_cert_chain_t, CertificateChainDelete> attest_key_chain(
        CreateAttestationChain(sign_algorithm, root_ca_cert, root_ca_cert_size, error));
    if (!attest_key_chain.get()) {
        ALOGE("CreateAttestationChain Failed");
        return false;
    }

    ALOGI("attest_key_chain->entry_count = %zu", attest_key_chain->entry_count);

    if (!allocate_cert_chain(attest_key_chain->entry_count + 1, chain, error))
        return false;

    chain->entries[0].data = nullptr;  // Leave empty for the leaf certificate.
    chain->entries[1].data_length = 0;

    for (size_t i = 0; i < attest_key_chain->entry_count; ++i) {
        chain->entries[i + 1] = attest_key_chain->entries[i];
        attest_key_chain->entries[i].data = nullptr;
    }
    ALOGI("Returning from %s", __FUNCTION__);

    return true;
}

bool add_public_key(EVP_PKEY* key, X509* certificate, keymaster_error_t* error) {
    if (!X509_set_pubkey(certificate, key)) {
        *error = TranslateLastOpenSslError();
        return false;
    }
    return true;
}

static keymaster_error_t build_auth_list(const AuthorizationSet& auth_list, KM_AUTH_LIST* record) {
    ENSURE_OR_GO_EXIT(record);

    if (auth_list.empty())
        return KM_ERROR_OK;

    for (auto entry : auth_list) {

        ASN1_INTEGER_SET** integer_set = nullptr;
        ASN1_INTEGER** integer_ptr = nullptr;
        ASN1_OCTET_STRING** string_ptr = nullptr;
        ASN1_NULL** bool_ptr = nullptr;

        switch (entry.tag) {

        /* Ignored tags */
        case KM_TAG_INVALID:
        case KM_TAG_ASSOCIATED_DATA:
        case KM_TAG_NONCE:
        case KM_TAG_AUTH_TOKEN:
        case KM_TAG_MAC_LENGTH:
        case KM_TAG_ALL_USERS:
        case KM_TAG_USER_ID:
        case KM_TAG_USER_SECURE_ID:
        case KM_TAG_EXPORTABLE:
        case KM_TAG_RESET_SINCE_ID_ROTATION:
        case KM_TAG_ATTESTATION_CHALLENGE:
        case KM_TAG_BLOCK_MODE:
        case KM_TAG_CALLER_NONCE:
        case KM_TAG_MIN_MAC_LENGTH:
        case KM_TAG_ECIES_SINGLE_HASH_MODE:
        case KM_TAG_INCLUDE_UNIQUE_ID:
        case KM_TAG_BLOB_USAGE_REQUIREMENTS:
        case KM_TAG_BOOTLOADER_ONLY:
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
        case KM_TAG_MAX_USES_PER_BOOT:
        case KM_TAG_APPLICATION_DATA:
        case KM_TAG_UNIQUE_ID:
        case KM_TAG_ROOT_OF_TRUST:
            continue;

        /* Non-repeating enumerations */
        case KM_TAG_ALGORITHM:
            integer_ptr = &record->algorithm;
            break;
        case KM_TAG_EC_CURVE:
            integer_ptr = &record->ec_curve;
            break;
        case KM_TAG_USER_AUTH_TYPE:
            integer_ptr = &record->user_auth_type;
            break;
        case KM_TAG_ORIGIN:
            integer_ptr = &record->origin;
            break;

        /* Repeating enumerations */
        case KM_TAG_PURPOSE:
            integer_set = &record->purpose;
            break;
        case KM_TAG_PADDING:
            integer_set = &record->padding;
            break;
        case KM_TAG_DIGEST:
            integer_set = &record->digest;
            break;
        case KM_TAG_KDF:
            integer_set = &record->kdf;
            break;

        /* Non-repeating unsigned integers */
        case KM_TAG_KEY_SIZE:
            integer_ptr = &record->key_size;
            break;
        case KM_TAG_AUTH_TIMEOUT:
            integer_ptr = &record->auth_timeout;
            break;
        case KM_TAG_OS_VERSION:
            integer_ptr = &record->os_version;
            break;
        case KM_TAG_OS_PATCHLEVEL:
            integer_ptr = &record->os_patchlevel;
            break;

        /* Non-repeating long unsigned integers */
        case KM_TAG_RSA_PUBLIC_EXPONENT:
            integer_ptr = &record->rsa_public_exponent;
            break;

        /* Dates */
        case KM_TAG_ACTIVE_DATETIME:
            integer_ptr = &record->active_date_time;
            break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
            integer_ptr = &record->origination_expire_date_time;
            break;
        case KM_TAG_USAGE_EXPIRE_DATETIME:
            integer_ptr = &record->usage_expire_date_time;
            break;
        case KM_TAG_CREATION_DATETIME:
            integer_ptr = &record->creation_date_time;
            break;

        /* Booleans */
        case KM_TAG_NO_AUTH_REQUIRED:
            bool_ptr = &record->no_auth_required;
            break;
        case KM_TAG_ALL_APPLICATIONS:
            bool_ptr = &record->all_applications;
            break;
        case KM_TAG_ROLLBACK_RESISTANT:
            bool_ptr = &record->rollback_resistant;
            break;
        case KM_TAG_ALLOW_WHILE_ON_BODY:
            bool_ptr = &record->allow_while_on_body;
            break;

        /* Byte arrays*/
        case KM_TAG_APPLICATION_ID:
            string_ptr = &record->application_id;
            break;
        case KM_TAG_ATTESTATION_APPLICATION_ID:
            string_ptr = &record->attestation_application_id;
            break;
        case KM_TAG_ATTESTATION_ID_BRAND:
            string_ptr = &record->attestation_id_brand;
            break;
        case KM_TAG_ATTESTATION_ID_DEVICE:
            string_ptr = &record->attestation_id_device;
            break;
        case KM_TAG_ATTESTATION_ID_PRODUCT:
            string_ptr = &record->attestation_id_product;
            break;
        case KM_TAG_ATTESTATION_ID_SERIAL:
            string_ptr = &record->attestation_id_serial;
            break;
        case KM_TAG_ATTESTATION_ID_IMEI:
            string_ptr = &record->attestation_id_imei;
            break;
        case KM_TAG_ATTESTATION_ID_MEID:
            string_ptr = &record->attestation_id_meid;
            break;
        case KM_TAG_ATTESTATION_ID_MANUFACTURER:
            string_ptr = &record->attestation_id_manufacturer;
            break;
        case KM_TAG_ATTESTATION_ID_MODEL:
            string_ptr = &record->attestation_id_model;
            break;
        default:
            continue;
        }

        keymaster_tag_type_t type = keymaster_tag_get_type(entry.tag);
        switch (type) {
        case KM_ENUM:
        case KM_ENUM_REP:
        case KM_UINT:
        case KM_UINT_REP: {
            ENSURE_OR_BREAK((keymaster_tag_repeatable(entry.tag) && integer_set) ||
                            (!keymaster_tag_repeatable(entry.tag) && integer_ptr));
            UniquePtr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(ASN1_INTEGER_new());
            if (!value.get())
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;
            if (!ASN1_INTEGER_set(value.get(), get_uint32_value(entry)))
                return TranslateLastOpenSslError();

            insert_integer(value.release(), integer_ptr, integer_set);
            break;
        }

        case KM_ULONG:
        case KM_ULONG_REP:
        case KM_DATE: {
            ENSURE_OR_BREAK((keymaster_tag_repeatable(entry.tag) && integer_set) ||
                            (!keymaster_tag_repeatable(entry.tag) && integer_ptr));
            UniquePtr<BIGNUM, BIGNUM_Delete> bn_value(BN_new());
            if (!bn_value.get())
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;

            if (type == KM_DATE) {
                if (!BN_set_u64(bn_value.get(), entry.date_time)) {
                    return TranslateLastOpenSslError();
                }
            } else {
                if (!BN_set_u64(bn_value.get(), entry.long_integer)) {
                    return TranslateLastOpenSslError();
                }
            }

            UniquePtr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(
                BN_to_ASN1_INTEGER(bn_value.get(), nullptr));
            if (!value.get())
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;

            insert_integer(value.release(), integer_ptr, integer_set);
            break;
        }

        case KM_BOOL:
            ENSURE_OR_BREAK(bool_ptr);
            if (!*bool_ptr)
                *bool_ptr = ASN1_NULL_new();
            if (!*bool_ptr)
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;
            break;

        /* Byte arrays*/
        case KM_BYTES:
            ENSURE_OR_BREAK(string_ptr);
            if (!*string_ptr)
                *string_ptr = ASN1_OCTET_STRING_new();
            if (!*string_ptr)
                return KM_ERROR_MEMORY_ALLOCATION_FAILED;
            if (!ASN1_OCTET_STRING_set(*string_ptr, entry.blob.data, entry.blob.data_length))
                return TranslateLastOpenSslError();
            break;

        default:
            return KM_ERROR_UNIMPLEMENTED;
        }
    }

    keymaster_ec_curve_t ec_curve;
    uint32_t key_size;
    if (auth_list.Contains(TAG_ALGORITHM, KM_ALGORITHM_EC) &&  //
        !auth_list.Contains(TAG_EC_CURVE) &&                   //
        auth_list.GetTagValue(TAG_KEY_SIZE, &key_size)) {
        // This must be a keymaster1 key. It's an EC key with no curve.  Insert the curve.

        keymaster_error_t error = EcKeySizeToCurve(key_size, &ec_curve);
        if (error != KM_ERROR_OK)
            return error;

        UniquePtr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(ASN1_INTEGER_new());
        if (!value.get())
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;

        if (!ASN1_INTEGER_set(value.get(), ec_curve))
            return TranslateLastOpenSslError();

        insert_integer(value.release(), &record->ec_curve, nullptr);
    }

    return KM_ERROR_OK;

exit:
    return KM_ERROR_UNEXPECTED_NULL_POINTER;
}

// Construct an ASN1.1 DER-encoded attestation record containing the values from sw_enforced and
// tee_enforced.
keymaster_error_t build_attestation_record(const AuthorizationSet& attestation_params,
                                           AuthorizationSet sw_enforced,
                                           AuthorizationSet tee_enforced,
                                           UniquePtr<uint8_t[]>* asn1_key_desc,
                                           size_t* asn1_key_desc_len) {
    if (!asn1_key_desc || !asn1_key_desc_len)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    UniquePtr<KM_KEY_DESCRIPTION, KM_KEY_DESCRIPTION_Delete> key_desc(KM_KEY_DESCRIPTION_new());
    if (!key_desc.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    keymaster_security_level_t keymaster_security_level;
    keymaster_security_level = KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    uint32_t keymaster_version = UINT32_MAX;
    keymaster_version = kCurrentKeymasterVersion;

    // Root of trust is only available in TEE
    KM_AUTH_LIST* tee_record = key_desc->tee_enforced;
    tee_record->root_of_trust = KM_ROOT_OF_TRUST_new();
    keymaster_blob_t verified_boot_key = {nullptr, 0};
    keymaster_verified_boot_t verified_boot_state = KM_VERIFIED_BOOT_UNVERIFIED;
    bool device_locked = false;
    // keymaster_error_t error = context.GetVerifiedBootParams(
    //     &verified_boot_key, &verified_boot_state, &device_locked);
    // if (error != KM_ERROR_OK)
    //     return error;
    if (verified_boot_key.data_length &&
        !ASN1_OCTET_STRING_set(tee_record->root_of_trust->verified_boot_key, verified_boot_key.data,
                               verified_boot_key.data_length)) {
        ALOGE("Failed setting RoT key");
        return TranslateLastOpenSslError();
    }
    tee_record->root_of_trust->device_locked = (int*)device_locked;
    if (!ASN1_ENUMERATED_set(tee_record->root_of_trust->verified_boot_state, verified_boot_state)) {
        ALOGE("Failed setting RoT boot state");
        return TranslateLastOpenSslError();
    }

    if (!ASN1_INTEGER_set(key_desc->attestation_version, kCurrentAttestationVersion) ||
        /*!ASN1_ENUMERATED_set(key_desc->attestation_security_level, context.GetSecurityLevel())
           ||*/
        !ASN1_ENUMERATED_set(key_desc->attestation_security_level, keymaster_security_level) ||
        !ASN1_INTEGER_set(key_desc->keymaster_version, keymaster_version) ||
        !ASN1_ENUMERATED_set(key_desc->keymaster_security_level, keymaster_security_level))
        return TranslateLastOpenSslError();

    keymaster_blob_t attestation_challenge = {nullptr, 0};
    if (!attestation_params.GetTagValue(TAG_ATTESTATION_CHALLENGE, &attestation_challenge))
        return KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
    if (!ASN1_OCTET_STRING_set(key_desc->attestation_challenge, attestation_challenge.data,
                               attestation_challenge.data_length))
        return TranslateLastOpenSslError();

    keymaster_blob_t attestation_app_id;
    if (!attestation_params.GetTagValue(TAG_ATTESTATION_APPLICATION_ID, &attestation_app_id))
        return KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
    sw_enforced.push_back(TAG_ATTESTATION_APPLICATION_ID, attestation_app_id);

    /* Following is for ID attestation.
     * We can skip till we don't support it.
     */

    /*keymaster_error_t error = context.VerifyAndCopyDeviceIds(
        attestation_params,
        keymaster_security_level == KM_SECURITY_LEVEL_SOFTWARE ? &sw_enforced : &tee_enforced);
    if (error == KM_ERROR_UNIMPLEMENTED) {
        // The KeymasterContext implementation does not support device ID attestation. Bail out if
        // device ID attestation is being attempted.
        for (const auto& tag : kDeviceAttestationTags) {
            if (attestation_params.find(tag) != -1) {
                return KM_ERROR_CANNOT_ATTEST_IDS;
            }
        }
    } else if (error != KM_ERROR_OK) {
        return error;
    }*/

    keymaster_error_t error = build_auth_list(sw_enforced, key_desc->software_enforced);
    if (error != KM_ERROR_OK)
        return error;

    error = build_auth_list(tee_enforced, key_desc->tee_enforced);
    if (error != KM_ERROR_OK)
        return error;

        /* Skip for now.
         * Need to check how UNIQUE_ID is used in attestation
         */
        // Only check tee_enforced for TAG_INCLUDE_UNIQUE_ID.  If we don't have hardware we can't
        // generate unique IDs.
#if 0
    if (tee_enforced.GetTagValue(TAG_INCLUDE_UNIQUE_ID)) {
        uint64_t creation_datetime;
        // Only check sw_enforced for TAG_CREATION_DATETIME, since it shouldn't be in tee_enforced,
        // since this implementation has no secure wall clock.
        if (!sw_enforced.GetTagValue(TAG_CREATION_DATETIME, &creation_datetime)) {
            LOG_E("Unique ID cannot be created without creation datetime", 0);
            return KM_ERROR_INVALID_KEY_BLOB;
        }

        keymaster_blob_t application_id = {nullptr, 0};
        sw_enforced.GetTagValue(TAG_APPLICATION_ID, &application_id);

        Buffer unique_id;
        error = context.GenerateUniqueId(
            creation_datetime, application_id,
            attestation_params.GetTagValue(TAG_RESET_SINCE_ID_ROTATION), &unique_id);
        if (error != KM_ERROR_OK) {
            return error;
        }

        key_desc->unique_id = ASN1_OCTET_STRING_new();
        if (!key_desc->unique_id ||
            !ASN1_OCTET_STRING_set(key_desc->unique_id, unique_id.peek_read(),
                                   unique_id.available_read()))
            return TranslateLastOpenSslError();
    }
#endif
    int len = i2d_KM_KEY_DESCRIPTION(key_desc.get(), nullptr);
    if (len < 0)
        return TranslateLastOpenSslError();
    *asn1_key_desc_len = len;
    asn1_key_desc->reset(new (std::nothrow) uint8_t[*asn1_key_desc_len]);
    if (!asn1_key_desc->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    uint8_t* p = asn1_key_desc->get();
    len = i2d_KM_KEY_DESCRIPTION(key_desc.get(), &p);
    if (len < 0)
        return TranslateLastOpenSslError();

    return KM_ERROR_OK;
}

static keymaster_error_t build_attestation_extension(const AuthorizationSet& attest_params,
                                                     const AuthorizationSet& tee_enforced,
                                                     const AuthorizationSet& sw_enforced,
                                                     X509_EXTENSION_Ptr* extension) {
    ASN1_OBJECT_Ptr oid(
        OBJ_txt2obj(kAttestionRecordOid, 1 /* accept numerical dotted string form only */));
    if (!oid.get())
        return TranslateLastOpenSslError();

    UniquePtr<uint8_t[]> attest_bytes;
    size_t attest_bytes_len;
    keymaster_error_t error = build_attestation_record(attest_params, sw_enforced, tee_enforced,
                                                       &attest_bytes, &attest_bytes_len);
    if (error != KM_ERROR_OK)
        return error;

    ASN1_OCTET_STRING_Ptr attest_str(ASN1_OCTET_STRING_new());
    if (!attest_str.get() ||
        !ASN1_OCTET_STRING_set(attest_str.get(), attest_bytes.get(), attest_bytes_len))
        return TranslateLastOpenSslError();

    extension->reset(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0 /* not critical */, attest_str.get()));
    if (!extension->get())
        return TranslateLastOpenSslError();

    return KM_ERROR_OK;
}

bool add_attestation_extension(const AuthorizationSet& attest_params,
                               const AuthorizationSet& tee_enforced,
                               const AuthorizationSet& sw_enforced, X509* certificate,
                               keymaster_error_t* error) {
    X509_EXTENSION_Ptr attest_extension;
    *error =
        build_attestation_extension(attest_params, tee_enforced, sw_enforced, &attest_extension);
    if (*error != KM_ERROR_OK)
        return false;

    if (!X509_add_ext(certificate, attest_extension.get() /* Don't release; copied */,
                      -1 /* insert at end */)) {
        *error = TranslateLastOpenSslError();
        return false;
    }

    return true;
}

// Copy all enumerated values with the specified tag from stack to auth_list.
static bool get_repeated_enums(const stack_st_ASN1_INTEGER* stack, keymaster_tag_t tag,
                               AuthorizationSet* auth_list) {
    assert(keymaster_tag_get_type(tag) == KM_ENUM_REP);
    for (size_t i = 0; i < sk_ASN1_INTEGER_num(stack); ++i) {
        if (!auth_list->push_back(
                keymaster_param_enum(tag, ASN1_INTEGER_get(sk_ASN1_INTEGER_value(stack, i)))))
            return false;
    }
    return true;
}

// Add the specified integer tag/value pair to auth_list.
template <keymaster_tag_type_t Type, keymaster_tag_t Tag, typename KeymasterEnum>
static bool get_enum(const ASN1_INTEGER* asn1_int, TypedEnumTag<Type, Tag, KeymasterEnum> tag,
                     AuthorizationSet* auth_list) {
    if (!asn1_int)
        return true;
    return auth_list->push_back(tag, static_cast<KeymasterEnum>(ASN1_INTEGER_get(asn1_int)));
}

// Add the specified ulong tag/value pair to auth_list.
static bool get_ulong(const ASN1_INTEGER* asn1_int, keymaster_tag_t tag,
                      AuthorizationSet* auth_list) {
    if (!asn1_int)
        return true;
    UniquePtr<BIGNUM, BIGNUM_Delete> bn(ASN1_INTEGER_to_BN(asn1_int, nullptr));
    if (!bn.get())
        return false;
    uint64_t ulong = BN_get_word(bn.get());
    return auth_list->push_back(keymaster_param_long(tag, ulong));
}

// Extract the values from the specified ASN.1 record and place them in auth_list.
static keymaster_error_t extract_auth_list(const KM_AUTH_LIST* record,
                                           AuthorizationSet* auth_list) {
    if (!record)
        return KM_ERROR_OK;

    // Purpose
    if (!get_repeated_enums(record->purpose, TAG_PURPOSE, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Algorithm
    if (!get_enum(record->algorithm, TAG_ALGORITHM, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Key size
    if (record->key_size && !auth_list->push_back(TAG_KEY_SIZE, ASN1_INTEGER_get(record->key_size)))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Digest
    if (!get_repeated_enums(record->digest, TAG_DIGEST, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Padding
    if (!get_repeated_enums(record->padding, TAG_PADDING, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // EC curve
    if (!get_enum(record->ec_curve, TAG_EC_CURVE, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // RSA public exponent
    if (!get_ulong(record->rsa_public_exponent, TAG_RSA_PUBLIC_EXPONENT, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Active date time
    if (!get_ulong(record->active_date_time, TAG_ACTIVE_DATETIME, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Origination expire date time
    if (!get_ulong(record->origination_expire_date_time, TAG_ORIGINATION_EXPIRE_DATETIME,
                   auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Usage Expire date time
    if (!get_ulong(record->usage_expire_date_time, TAG_USAGE_EXPIRE_DATETIME, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // No auth required
    if (record->no_auth_required && !auth_list->push_back(TAG_NO_AUTH_REQUIRED))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // User auth type
    if (!get_enum(record->user_auth_type, TAG_USER_AUTH_TYPE, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Auth timeout
    if (record->auth_timeout &&
        !auth_list->push_back(TAG_AUTH_TIMEOUT, ASN1_INTEGER_get(record->auth_timeout)))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // All applications
    if (record->all_applications && !auth_list->push_back(TAG_ALL_APPLICATIONS))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Application ID
    if (record->application_id &&
        !auth_list->push_back(TAG_APPLICATION_ID, record->application_id->data,
                              record->application_id->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Creation date time
    if (!get_ulong(record->creation_date_time, TAG_CREATION_DATETIME, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Origin
    if (!get_enum(record->origin, TAG_ORIGIN, auth_list))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Rollback resistant
    if (record->rollback_resistant && !auth_list->push_back(TAG_ROLLBACK_RESISTANT))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Root of trust
    if (record->root_of_trust) {
        KM_ROOT_OF_TRUST* rot = record->root_of_trust;
        if (!rot->verified_boot_key)
            return KM_ERROR_INVALID_KEY_BLOB;

        // Other root of trust fields are not mapped to auth set entries.
    }

    // OS Version
    if (record->os_version &&
        !auth_list->push_back(TAG_OS_VERSION, ASN1_INTEGER_get(record->os_version)))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // OS Patch level
    if (record->os_patchlevel &&
        !auth_list->push_back(TAG_OS_PATCHLEVEL, ASN1_INTEGER_get(record->os_patchlevel)))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Brand name
    if (record->attestation_id_brand &&
        !auth_list->push_back(TAG_ATTESTATION_ID_BRAND, record->attestation_id_brand->data,
                              record->attestation_id_brand->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Device name
    if (record->attestation_id_device &&
        !auth_list->push_back(TAG_ATTESTATION_ID_DEVICE, record->attestation_id_device->data,
                              record->attestation_id_device->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Product name
    if (record->attestation_id_product &&
        !auth_list->push_back(TAG_ATTESTATION_ID_PRODUCT, record->attestation_id_product->data,
                              record->attestation_id_product->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Serial number
    if (record->attestation_id_serial &&
        !auth_list->push_back(TAG_ATTESTATION_ID_SERIAL, record->attestation_id_serial->data,
                              record->attestation_id_serial->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // IMEI
    if (record->attestation_id_imei &&
        !auth_list->push_back(TAG_ATTESTATION_ID_IMEI, record->attestation_id_imei->data,
                              record->attestation_id_imei->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // MEID
    if (record->attestation_id_meid &&
        !auth_list->push_back(TAG_ATTESTATION_ID_MEID, record->attestation_id_meid->data,
                              record->attestation_id_meid->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Manufacturer name
    if (record->attestation_id_manufacturer &&
        !auth_list->push_back(TAG_ATTESTATION_ID_MANUFACTURER,
                              record->attestation_id_manufacturer->data,
                              record->attestation_id_manufacturer->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    // Model name
    if (record->attestation_id_model &&
        !auth_list->push_back(TAG_ATTESTATION_ID_MODEL, record->attestation_id_model->data,
                              record->attestation_id_model->length))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    return KM_ERROR_OK;
}

// Parse the DER-encoded attestation record, placing the results in keymaster_version,
// attestation_challenge, software_enforced, tee_enforced and unique_id.
keymaster_error_t parse_attestation_record(const uint8_t* asn1_key_desc, size_t asn1_key_desc_len,
                                           uint32_t* attestation_version,  //
                                           keymaster_security_level_t* attestation_security_level,
                                           uint32_t* keymaster_version,
                                           keymaster_security_level_t* keymaster_security_level,
                                           keymaster_blob_t* attestation_challenge,
                                           AuthorizationSet* software_enforced,
                                           AuthorizationSet* tee_enforced,
                                           keymaster_blob_t* unique_id) {
    const uint8_t* p = asn1_key_desc;
    UniquePtr<KM_KEY_DESCRIPTION, KM_KEY_DESCRIPTION_Delete> record(
        d2i_KM_KEY_DESCRIPTION(nullptr, &p, asn1_key_desc_len));
    if (!record.get())
        return TranslateLastOpenSslError();

    *attestation_version = ASN1_INTEGER_get(record->attestation_version);
    *attestation_security_level = static_cast<keymaster_security_level_t>(
        ASN1_ENUMERATED_get(record->attestation_security_level));
    *keymaster_version = ASN1_INTEGER_get(record->keymaster_version);
    *keymaster_security_level = static_cast<keymaster_security_level_t>(
        ASN1_ENUMERATED_get(record->keymaster_security_level));

    attestation_challenge->data =
        dup_buffer(record->attestation_challenge->data, record->attestation_challenge->length);
    attestation_challenge->data_length = record->attestation_challenge->length;

    unique_id->data = dup_buffer(record->unique_id->data, record->unique_id->length);
    unique_id->data_length = record->unique_id->length;

    keymaster_error_t error = extract_auth_list(record->software_enforced, software_enforced);
    if (error != KM_ERROR_OK)
        return error;

    return extract_auth_list(record->tee_enforced, tee_enforced);
}

}  // namespace keymaster