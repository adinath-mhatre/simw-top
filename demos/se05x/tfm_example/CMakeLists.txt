# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(tfm_example)
FILE(
    GLOB
    files
    *.c
)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ${SIMW_TOP_DIR}/sss/plugin/psa/inc
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    ex_common
    mbedtls
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S AND SSS_HAVE_MBEDTLS_ALT_PSA)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} PSA_ALT)
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
