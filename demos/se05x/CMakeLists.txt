#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

IF(SSS_HAVE_RTOS_DEFAULT)
    IF(SSS_HAVE_SE05X_VER_GTE_07_02)
        ADD_SUBDIRECTORY(sa_qi)
    ENDIF()
    ADD_SUBDIRECTORY(se05x_ConcurrentEcc)
    ADD_SUBDIRECTORY(se05x_ConcurrentSymm)

    IF(NOT SSS_HAVE_HOST_WIN10IOT)
        ADD_SUBDIRECTORY(se05x_Minimal)
    ENDIF()

    IF(SSS_HAVE_HOST_WITH_FILE_SYSTEM)
        ADD_SUBDIRECTORY(se05x_export)
        ADD_SUBDIRECTORY(se05x_import)
        IF(SSS_HAVE_HOSTCRYPTO_ANY)
            IF(SSS_HAVE_SE05X_AUTH_ECKEY)
                ADD_SUBDIRECTORY(se05x_ImportExternalObjectPrepare)
            ENDIF()
        ENDIF(SSS_HAVE_HOSTCRYPTO_ANY)
    ENDIF()

    IF(NOT SSS_HAVE_KSDK)
        IF(SSS_HAVE_SE05X_VER_GTE_06_00 AND (NOT SSS_HAVE_APPLET_AUTH))
            ADD_SUBDIRECTORY(se05x_Personalization)
        ENDIF()
        IF(CMAKE_COMPILER_IS_GNUCC)
            ADD_SUBDIRECTORY(se05x_MultiThread)
        ENDIF()
    ENDIF()

    IF(SSSFTR_SE05X_AuthSession AND SSS_HAVE_HOSTCRYPTO_ANY)
        IF(SSS_HAVE_SE05X_AUTH_NONE OR SSS_HAVE_SE05X_AUTH_PLATFSCP03)
            ADD_SUBDIRECTORY(se05x_Delete_and_test_provision)
            ADD_SUBDIRECTORY(se05x_MandatePlatformSCP)
        ELSE()
            MESSAGE(STATUS "se05x_Delete_and_test_provision is not built because SE05X_Auth is '${SE05X_Auth}'.")
        ENDIF()
    ENDIF(SSSFTR_SE05X_AuthSession AND SSS_HAVE_HOSTCRYPTO_ANY)

    IF(SSS_HAVE_SE05X_AUTH_PLATFSCP03)
        ADD_SUBDIRECTORY(se05x_RotatePlatformSCP03Keys)
        ADD_SUBDIRECTORY(se05x_AllowWithoutPlatformSCP)
        IF(SSS_HAVE_SMCOM_T1OI2C AND SSS_HAVE_HOST_WITH_FILE_SYSTEM)
            ADD_SUBDIRECTORY(se05x_scp03_boot)
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_SE05X_VER_GTE_06_00 AND SSS_HAVE_RSA)
        ADD_SUBDIRECTORY(se05x_Perso_Delete_Mod_RSAKeyGen)
    ENDIF()

    IF(SSSFTR_SE05X_AuthSession AND SSS_HAVE_HOSTCRYPTO_ANY)
        IF(SSS_HAVE_SE05X_AUTH_NONE OR SSS_HAVE_SE05X_AUTH_PLATFSCP03)
            ADD_SUBDIRECTORY(se05x_TransportLock)
            ADD_SUBDIRECTORY(se05x_TransportUnLock)
        ENDIF()
    ENDIF(SSSFTR_SE05X_AuthSession AND SSS_HAVE_HOSTCRYPTO_ANY)

    IF((NOT SSS_HAVE_HOST_WIN10IOT) AND SSS_HAVE_PBKDF2)
        ADD_SUBDIRECTORY(ex_se05x_WiFiKDF)
    ENDIF()

    ADD_SUBDIRECTORY(se05x_GetInfo)

    IF(NOT SSS_HAVE_APPLET_AUTH)
        ADD_SUBDIRECTORY(se05x_PCR)
    ENDIF()

    IF(NOT SSS_HAVE_APPLET_AUTH)
        ADD_SUBDIRECTORY(se05x_I2cMaster)
    ENDIF()

    ADD_SUBDIRECTORY(se05x_MultipleDigestCryptoObj)

    IF(SSS_HAVE_SE05X_VER_GTE_06_00)
        ADD_SUBDIRECTORY(se05x_ReadState)
    ENDIF()

    IF(SSS_HAVE_ECC)
        ADD_SUBDIRECTORY(se05x_policy)
    ENDIF()

    IF(SSS_HAVE_HOSTCRYPTO_ANY)
        ADD_SUBDIRECTORY(se05x_ReadWithAttestation)
    ENDIF()

    IF(SSS_HAVE_SCP_None)
        ADD_SUBDIRECTORY(se05x_GetAPDUBuffer)
    ENDIF()
    IF(SSS_HAVE_HOSTCRYPTO_ANY)
        ADD_SUBDIRECTORY(se05x_TimeStamp)
    ENDIF()
    ADD_SUBDIRECTORY(se05x_InjectCertificate)

    IF(SSS_HAVE_SE05X_AUTH_ECKEY OR SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)
        IF(NOT SSS_HAVE_APPLET_AUTH)
            ADD_SUBDIRECTORY(se05x_SetAppletFeatures)
        ENDIF()
        # ADD_SUBDIRECTORY(se05x_DesfireCRC)
    ENDIF()

    ADD_SUBDIRECTORY(se05x_InvokeGarbageCollection)
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_SUBDIRECTORY(se05x_Minimal)
    ADD_SUBDIRECTORY(se05x_GetInfo)
    IF(SSS_HAVE_KSDK)
        ADD_SUBDIRECTORY(se05x_MultiThread)
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    ADD_SUBDIRECTORY(certificate_demo)
    ADD_SUBDIRECTORY(seTool)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND NOT SSS_HAVE_KSDK)
    ADD_SUBDIRECTORY(se05x_GetCertificate)
ENDIF()

IF(NXPProprietary)
    IF(SSS_HAVE_MBEDTLS_ALT_PSA)
        IF(SSS_HAVE_HOST_LPCXPRESSO55S)
            ADD_SUBDIRECTORY(tfm_example)
        ENDIF()
        IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS AND (NOT SSS_HAVE_APPLET_AUTH))
            ADD_SUBDIRECTORY(psa_nonsecure)
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS AND SSS_HAVE_MBEDTLS_ALT_SSS)
    ADD_SUBDIRECTORY(pkcs11)
ENDIF()
