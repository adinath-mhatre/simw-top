# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#
PROJECT(se05x_MultiThread)

FILE(
    GLOB
    files
    *.c
    *.h
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
    SSS_APIs
    ex_common
)

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT SSS_HAVE_KSDK))
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lpthread)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND SSS_HAVE_KSDK)
    # See https://jira.sw.nxp.com/browse/SIMW-3123
    IF(${CMAKE_CXX_COMPILER_VERSION} VERSION_GREATER 8.0)
        TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE -Wno-error=cast-function-type)
    ENDIF()
ENDIF()

EXPOSE_SE05X_AUTH_STRATEGY()
CREATE_BINARY(${PROJECT_NAME})
