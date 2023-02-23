#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(cloud_ibm_watson)

FILE(
    GLOB
    files
    ibm_client_credential_keys.h
    ibm_watson_default_root_certificate.h
    ibm_watson_demo_Main_lwip.c
    ibm_watson_iot_config.h
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
        ibm_watson_demo_Main_x86.c
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
