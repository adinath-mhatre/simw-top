#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(sems_lite_ex_update)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
)

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})


TARGET_LINK_LIBRARIES(${PROJECT_NAME} SEMS_LITE_AGENT_APIs)

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ../inc)

CREATE_BINARY(${PROJECT_NAME})
