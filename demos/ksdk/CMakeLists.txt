#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

SET(ADD_KSDK_DEMOS OFF)

IF(NXPInternal AND SSS_HAVE_HOST_PCWINDOWS)
    SET(ADD_KSDK_DEMOS ON)
ENDIF()

IF(UWBIOT_UWBD_SR150)
    SET(ADD_KSDK_DEMOS OFF)
ENDIF()

IF(SSS_HAVE_KSDK)
    SET(ADD_KSDK_DEMOS ON)
    ADD_SUBDIRECTORY(common/boards/${KSDK_BoardName})
ENDIF()

INCLUDE_DIRECTORIES(common)

IF(SSS_HAVE_HOSTCRYPTO_NONE)
    SET(ADD_KSDK_DEMOS OFF)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)
    SET(ADD_KSDK_DEMOS OFF)
ENDIF(SSS_HAVE_HOST_LPCXPRESSO55S_NS)

IF(NXPInternal)
    IF(SSS_HAVE_HOST_PCWINDOWS)
        ADD_SUBDIRECTORY(x86pc)
    ENDIF()
ENDIF()

IF(ADD_KSDK_DEMOS)
    IF(SSS_HAVE_MBEDTLS_ALT_SSS)
        IF(SSS_HAVE_RTOS_FREERTOS)
            ADD_SUBDIRECTORY(gcp)
            ADD_SUBDIRECTORY(azure)
            ADD_SUBDIRECTORY(aws_jitr)
            ADD_SUBDIRECTORY(ibm_watson)
        ELSE()
            MESSAGE(STATUS "Set RTOS=FreeRTOS to Build Cloud Examples ")
        ENDIF()
    ELSE()
        MESSAGE(STATUS "Set mbedTLS_ALT=SSS to Build Cloud Examples ")
    ENDIF()
    IF(SSS_HAVE_APPLET)
        ADD_SUBDIRECTORY(provisioning)
    ENDIF()
ENDIF()
