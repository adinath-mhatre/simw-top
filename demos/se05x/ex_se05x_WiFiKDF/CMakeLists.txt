#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(ex_se05x_WiFiKDF_derive)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${PROJECT_NAME}.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})

PROJECT(ex_se05x_WiFiKDF_inject)

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE} ${PROJECT_NAME}.c
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    ex_common
)

CREATE_BINARY(${PROJECT_NAME})
