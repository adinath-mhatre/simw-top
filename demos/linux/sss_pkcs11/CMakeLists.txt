#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(sss_pkcs11)

FILE(
    GLOB
    files
    ${PROJECT_NAME}.c
)

FILE(
    GLOB
    pkcs11_files
    ${SIMW_TOP_DIR}/sss/plugin/pkcs11/*.c
)

ADD_DEFINITIONS(-DPKCS11_LIBRARY)
ADD_DEFINITIONS(-DPKCS11_SESSION_OPEN)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${files} ${pkcs11_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/demos/linux/sss_pkcs11/include
            #PKCS11 Dependencies
    PRIVATE ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/pkcs11
    PRIVATE ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/abstractions/pkcs11/corePKCS11/source/include
    PRIVATE ${SIMW_TOP_DIR}/sss/plugin/pkcs11
)

##PKCS11 Dependencies
TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC ${DEMOS_KSDK_DIR}/common
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ex_common
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

COPY_TO_SOURCEDIR(
    ${PROJECT_NAME}
    binaries/pkcs11
    ${SMCOM}
)
