#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(pkcs11)

FILE(
    GLOB
    files
    ${SIMW_TOP_DIR}/sss/plugin/pkcs11/*.c
)

ADD_DEFINITIONS(-DPKCS11_SESSION_OPEN)

ADD_LIBRARY(${PROJECT_NAME} ${files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/pkcs11
    PUBLIC ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/freertos_plus/standard/crypto/include
    PUBLIC ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/freertos_plus/standard/pkcs11/include
    PUBLIC ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/abstractions/pkcs11/corePKCS11/source/include
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4127 # conditional expression is constant
            /wd4267
            /wd4310
    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${DEMOS_KSDK_DIR}/common
    PUBLIC ${SIMW_TOP_DIR}/sss/plugin/pkcs11
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    freertos-kernel
)
