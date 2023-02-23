#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

ADD_SUBDIRECTORY(src)

IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)

    IF(
        SSS_HAVE_RTOS_DEFAULT
        AND (SSS_HAVE_APPLET_SE05X_IOT
             OR SSS_HAVE_APPLET_A71CH
             OR SSS_HAVE_APPLET_A71CH_SIM)
    )
        IF(SSS_HAVE_HOSTCRYPTO_ANY)
            ADD_SUBDIRECTORY(hkdf)
        ENDIF()
        IF(SSS_HAVE_HOSTCRYPTO_ANY)
            ADD_SUBDIRECTORY(ecdh)
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_APPLET_SE05X_IOT)
        ADD_SUBDIRECTORY(symmetric)
    ENDIF()

    IF(
        SSS_HAVE_APPLET_SE05X_IOT
        OR SSS_HAVE_APPLET_A71CH
        OR SSS_HAVE_APPLET_A71CH_SIM
    )
        ADD_SUBDIRECTORY(md)
        ADD_SUBDIRECTORY(hmac)
    ENDIF()

    IF(SSS_HAVE_ECC OR (SSS_HAVE_APPLET_NONE AND (SSS_HAVE_HOSTCRYPTO_OPENSSL OR SSS_HAVE_HOSTCRYPTO_MBEDTLS)))
        ADD_SUBDIRECTORY(ecc)
        IF(SSS_HAVE_TPM_BN OR (SSS_HAVE_APPLET_NONE AND (SSS_HAVE_HOSTCRYPTO_OPENSSL OR SSS_HAVE_HOSTCRYPTO_MBEDTLS)))
            IF(NXPInternal)
                ADD_SUBDIRECTORY(ecdaa)
            ENDIF()
        ENDIF()
        IF(SSS_HAVE_APPLET_SE05X_IOT)
            ADD_SUBDIRECTORY(attest_ecc)
            IF(SSS_HAVE_EC_MONT)
                ADD_SUBDIRECTORY(attest_mont)
            ENDIF()
            IF(SSS_HAVE_EC_ED)
                ADD_SUBDIRECTORY(eddsa)
            ENDIF()
        ENDIF()
    ENDIF()
    IF(SSS_HAVE_RSA OR (SSS_HAVE_APPLET_NONE AND (SSS_HAVE_HOSTCRYPTO_OPENSSL OR SSS_HAVE_HOSTCRYPTO_MBEDTLS)))
        IF(NOT SSS_HAVE_APPLET_SE051_UWB)
            ADD_SUBDIRECTORY(rsa)
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_KSDK)
        #No native mbedTLS Examples
    ELSE()
        IF(SSS_HAVE_MBEDTLS_ALT_SSS)
            ADD_SUBDIRECTORY(mbedtls)
        ENDIF()
    ENDIF()

ENDIF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
