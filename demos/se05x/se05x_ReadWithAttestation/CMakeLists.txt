# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(se05x_ReadWithAttestation)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${PROJECT_NAME}.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE .
)

EXPOSE_SE05X_AUTH_STRATEGY()
CREATE_BINARY(${PROJECT_NAME})
