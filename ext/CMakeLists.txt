# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

ADD_SUBDIRECTORY(unity)

IF(SSS_HAVE_SMCOM_JRCP_V2 OR SSS_HAVE_SMCOM_VCOM)
    IF(NXPProprietary)
        ADD_SUBDIRECTORY(jrcplib)
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    IF(WithCodeCoverage AND SSS_HAVE_HOST_PCWINDOWS)
    ELSE()
        IF(SSS_HAVE_OPENSSL_1_1_1)
            INCLUDE(paho.cmake)
        ENDIF()
    ENDIF()
    IF(NOT SSS_HAVE_HOST_LINUX_LIKE)
        IF(SSS_HAVE_OPENSSL_3_0)
            ADD_SUBDIRECTORY(openssl-30)
        ELSE()
            ADD_SUBDIRECTORY(openssl)
        ENDIF()
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    IF(SSS_HAVE_MBEDTLS_ALT_PSA)
        INCLUDE(mbed-crypto.cmake)
    ELSE()
        INCLUDE(mbedtls.cmake)
    ENDIF()
ENDIF()

IF(SSS_HAVE_RTOS_FREERTOS)
    INCLUDE(amazon-freertos.cmake)
ENDIF()

IF(SSS_HAVE_APPLET_A71CL OR SSS_HAVE_APPLET_SE05X_L)
    IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
        ADD_SUBDIRECTORY(id2_client_sdk)
    ENDIF()
ENDIF()

IF(SSS_HAVE_SMCOM_VCOM)
    IF("Windows" STREQUAL "${CMAKE_SYSTEM_NAME}")
        ADD_SUBDIRECTORY(JRCPProxyConsole)
    ENDIF()
ENDIF()

IF(SSS_HAVE_LOG_SEGGERRTT)
    ADD_SUBDIRECTORY(seggerrtt)
ENDIF()

IF(SSS_HAVE_SMCOM_PN7150)
    ADD_SUBDIRECTORY(PN7150Nfc)
ENDIF()

IF(WithNXPNFCRdLib)
    INCLUDE(nxpnfcrdlib.cmake)
ENDIF()

IF(WithOPCUA_open62541)
    IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND (SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_IMXLINUX OR SSS_HAVE_HOST_PCLINUX64 OR SSS_HAVE_HOST_RASPBIAN))
        INCLUDE(open62541.cmake)
    ENDIF()
ENDIF()


