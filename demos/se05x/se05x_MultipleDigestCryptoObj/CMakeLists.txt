#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x_MultipleDigestCryptoObj)

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
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

CREATE_BINARY(${PROJECT_NAME})

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()
