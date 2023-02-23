#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(cloud_gcp)

FILE(
    GLOB
    files
    gcpJWTDemo.c
    gcpJWTDemo.h
    gcpJWTDemo_Main_lwip.c
    gcpNTPGetEpoch_lwip.c
    gcpPubSub.c
    gcp_client_credential_keys.h
    gcp_default_root_certificates.h
    gcp_iot_config.h
    ../common/ledHandler.c
    ../common/*.h
)

IF(SSS_HAVE_MBEDTLS_ALT_SSS AND (SSS_HAVE_APPLET_A7XX OR SSS_HAVE_APPLET_SE050_EAR))
    LIST(
        APPEND
        files
        ${SIMW_TOP_DIR}/sss/ex/src/ex_sss_a71ch.c
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    LIST(
        APPEND
        files
        gcpJWTDemo_Main_x86.c
        gcpJwtTask_lwip.c
        gcpJwtTask_x86.c
        gcpNTPGetEpoch_time.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ../common/https_client ../common
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(ENABLE_CLOUD_DEMOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-ip)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
        )
    ENDIF()
ENDIF()
IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE -Wno-address-of-packed-member)
ENDIF()
