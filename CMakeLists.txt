# Copyright 2018,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

IF(
    ${CMAKE_SOURCE_DIR}
    STREQUAL
    ${CMAKE_BINARY_DIR}
)
    MESSAGE("\nUSAGE_ERROR:\n\n\tRun with cmake -S <SOURCE_DIR> -B <BUILD_DIR>\n")
    MESSAGE(
        FATAL_ERROR
            "In-source builds not allowed. Please make a new directory and run CMake from there.\n!!!IMPORTANT!!! Remove CMakeCache.txt and CMakeFiles!"
    )
ENDIF()

PROJECT(PlugAndTrustMW)

# Top DIR for SE
SET(SIMW_TOP_DIR "${CMAKE_SOURCE_DIR}")
SET(LOG_SRC_DIR "${CMAKE_SOURCE_DIR}/hostlib/hostLib/libCommon/log")

INCLUDE(scripts/cmake_options.cmake)

INCLUDE(scripts/git_version.cmake)

CONFIGURE_FILE(
    ${CMAKE_SOURCE_DIR}/demos/ksdk/common/git_version.h.in
    ${CMAKE_BINARY_DIR}/git_version.h
    @ONLY
)

SET(CMAKE_MODULE_PATH "./scripts")

INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

CONFIGURE_FILE(sss/inc/fsl_sss_ftr.h.in fsl_sss_ftr.h)
CONFIGURE_FILE(scripts/cmake_options.mak.in cmake_options.mak)
CONFIGURE_FILE(scripts/cmake_options_installed.cmake.in cmake_options_installed.cmake)

IF(NXPInternal)
    CONFIGURE_FILE(tst/sss/inc/pt_tst_ftr.h.in pt_tst_ftr.h)
ENDIF()

INSTALL(FILES ${CMAKE_BINARY_DIR}/fsl_sss_ftr.h DESTINATION ${SIMW_INSTALL_INC_DIR})
INSTALL(FILES ${CMAKE_BINARY_DIR}/cmake_options.mak DESTINATION ${SIMW_INSTALL_SHARE_DIR})
INSTALL(FILES ${CMAKE_BINARY_DIR}/cmake_options_installed.cmake DESTINATION ${SIMW_INSTALL_SHARE_DIR})

# EXT and DOC should not be dependent on any compile time variables/depednencies
# ESPECIALLY, SSS_USE_FTR_FILE and FLOW_VERBOSE

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DmqttconfigENABLE_METRICS=0)

IF(SSS_HAVE_LOG_SILENT)
    MESSAGE(STATUS "FLOW_SILENT is ON!!!")
    ADD_DEFINITIONS(-DFLOW_SILENT)
ENDIF()

ADD_SUBDIRECTORY(ext)
IF(NOT SSS_HAVE_LOG_SEGGERRTT)
    ADD_SUBDIRECTORY(${LOG_SRC_DIR})
ENDIF()

IF(NXPInternal)
    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        STREQUAL
        "MSVC"
    )
        # Macros won't work for MSVC
    ELSE()
        ADD_SUBDIRECTORY(exhaledocs)

    ENDIF()
ENDIF()

IF(SSS_HAVE_LOG_VERBOSE)
    MESSAGE(STATUS "FLOW_VERBOSE is ON!!!")
    ADD_DEFINITIONS(-DFLOW_VERBOSE)
ENDIF()

IF(WithCodeCoverage)
    IF(CMAKE_COMPILER_IS_GNUCXX)
        INCLUDE(scripts/CodeCoverage.cmake)
        APPEND_COVERAGE_COMPILER_FLAGS()
    ENDIF()
ENDIF()

ADD_SUBDIRECTORY(hostlib)

ADD_SUBDIRECTORY(sss)

IF(NXPInternal)
   ADD_SUBDIRECTORY(tst)
ENDIF()
IF(NXPProprietary)
    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
        IF(SSS_HAVE_SE05X_VER_GTE_06_00)
            ADD_SUBDIRECTORY(semslite)
        ENDIF()
    ENDIF()
ENDIF()

IF(WithExtCustomerTPMCode)
    IF(NOT SSS_HAVE_APPLET_AUTH)
        add_subdirectory(../customer/tpm2 extcust)
    ENDIF()
ENDIF()

ADD_SUBDIRECTORY(demos)

IF(NXPProprietary)
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        IF(SSS_HAVE_APPLET_SE05X_IOT)
            IF(SSS_HAVE_HOST_PCWINDOWS AND "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
                # NOTE-PGH: 2020.01.32 SimpleServer.exe does not compile
            ELSE()
                IF(SSS_HAVE_OPENSSL_1_1_1)
                    ADD_SUBDIRECTORY(nxp_iot_agent)
                ENDIF()
            ENDIF()
        ENDIF()
    ELSEIF(SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_MBEDTLS_ALT_SSS AND SSS_HAVE_APPLET_SE05X_IOT)
        # Build for FreeRTOS
        IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_RTOS_FREERTOS)
            # Build for Windows or Windows 10 IoT or RTOS
            ADD_SUBDIRECTORY(nxp_iot_agent)
        ENDIF()
    ENDIF()
ENDIF()

IF(NXPProprietary)
    IF(SSS_HAVE_APPLET_SE05X_IOT)
        ADD_SUBDIRECTORY(nxp_iot_agent/src/common)
    ENDIF()
ENDIF()
