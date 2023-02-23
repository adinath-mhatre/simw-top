#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(SSS_APIs LANGUAGES C)

FILE(
    GLOB
    API_FILES
    inc/*.h
    inc/*.h.in
    inc/*.hpp
    src/*.c
    src/sscp/fsl_sss_sscp.c
    src/a71ch/*.c
    src/a71cl/*.c
    src/user/*.c
    src/user/crypto/aes.c
    src/user/crypto/aes_cmac.c
    src/user/crypto/aes_cmac_multistep.c
    src/user/crypto/*.h
    src/se050/*.c
    src/se05x/*.c
    src/mbedtls/*.c
    src/mbedtls/*.cpp
    src/openssl/*.c
    src/keystore/*.c
    src/a71cx_common/*.c
    src/lpc55s/*.c
    port/default/*.h
    ../doc/input/doc_*.h
    cpp/*.cpp
    ${PlugAndTrustMW_BINARY_DIR}/fsl_sss_ftr.h
)

IF(SSS_HAVE_HOST_ANDROID)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${API_FILES})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${API_FILES})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC inc
)

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/ksdk)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/default)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ENDIF()

IF((SSS_HAVE_HOST_LINUX_LIKE OR SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_DARWIN OR SSS_HAVE_HOST_WIN10IOT))
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_USER)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC user/crypto)
ENDIF()

IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a71ch)
ENDIF()

IF(SSS_HAVE_APPLET_A71CL OR WithApplet_SE050_EAR_CL)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a71cl)
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        se05x
        a7x_utils
    )
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} smCom
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(SSS_HAVE_LARGE_PROGRAMS)
    ADD_SUBDIRECTORY(ex)
ELSE()
    ADD_SUBDIRECTORY(ex/src)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_ANY)
    IF(
        SSS_HAVE_APPLET_A71CH
        OR SSS_HAVE_APPLET_A71CH_SIM
        OR SSS_HAVE_APPLET_SE05X_IOT
    )
        IF(
            SSS_HAVE_HOST_PCWINDOWS
            OR SSS_HAVE_HOST_DARWIN
            OR SSS_HAVE_HOST_LINUX_LIKE
        )
            # ADD_SUBDIRECTORY(src/dll)
            PROJECT(sssapisw)
            IF(MSVC)
                IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
                    SET(def_file "src/dll/sssapisdll_a71ch.def")
                ENDIF()
                IF(SSS_HAVE_APPLET_SE05X_IOT)
                    IF(SSS_HAVE_SE05X_VER_GTE_07_02)
                        SET(def_file_06_08 "src/dll/sssapisdll_se05x_06_08.def")
                    ENDIF()
                    SET(def_file "src/dll/sssapisdll_se05x.def")
                ENDIF()
            ENDIF()
            ADD_LIBRARY(
                sssapisw SHARED
                ${API_FILES}
                ${def_file_06_08}
                ${def_file}
                src/dll/sssapisdll.c
            )
            TARGET_LINK_LIBRARIES(sssapisw SSS_APIs)
            ADD_CUSTOM_COMMAND(
                TARGET sssapisw
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sssapisw> ${SIMW_TOP_DIR}/tools
                COMMENT "Copy dll to ${SIMW_TOP_DIR}/tools"
            )
        ENDIF()
    ELSEIF(
        WithDllSupport
        AND SSS_HAVE_HOST_PCWINDOWS
        AND MSVC
    )
        # ADD_SUBDIRECTORY(src/dll)
        PROJECT(sssapisw)
        SET(def_file "src/dll/sssapisdll.def")
        ADD_LIBRARY(
            sssapisw SHARED
            ${API_FILES}
            ${def_file}
            src/dll/sssapisdll.c
        )
        TARGET_LINK_LIBRARIES(sssapisw SSS_APIs)
        ADD_CUSTOM_COMMAND(
            TARGET sssapisw
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sssapisw> ${SIMW_TOP_DIR}/tools
            COMMENT "Copy dll to ${SIMW_TOP_DIR}/tools"
        )
    ENDIF()

    IF((SSS_HAVE_HOST_LINUX_LIKE OR SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_DARWIN OR SSS_HAVE_HOST_WIN10IOT))
        IF(
            SSS_HAVE_APPLET_A71CH
            OR SSS_HAVE_APPLET_A71CH_SIM
            OR SSS_HAVE_APPLET_SE05X_IOT
            OR SSS_HAVE_HOSTCRYPTO_MBEDTLS
        )
            IF(NOT "${OPENSSL_LIBRARIES}" STREQUAL "")
                IF(SSS_HAVE_OPENSSL_1_1_1)
                    ADD_SUBDIRECTORY(plugin/openssl)
                ENDIF()
                IF(SSS_HAVE_OPENSSL_3_0)
                    ADD_SUBDIRECTORY(plugin/openssl_provider)
                ENDIF()
            ENDIF()
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_MBEDTLS_ALT_PSA)
        IF(SSS_HAVE_APPLET_SE05X_IOT)
            ADD_SUBDIRECTORY(plugin/psa)
        ENDIF()
    ENDIF()
    IF(UWBIOT_HOST_LINUX_LIKE)
        UWBIOT_INSTALL_LIBRARY(${PROJECT_NAME})
        INSTALL(
            DIRECTORY inc/ port/default/
            DESTINATION ${UWBIOT_INSTALL_INC_DIR}
            FILES_MATCHING
            PATTERN "*.h"
        )
    ELSEIF(SSS_HAVE_HOST_LINUX_LIKE)
        INSTALL(
            DIRECTORY inc/ port/default/
            DESTINATION ${SIMW_INSTALL_INC_DIR}
            FILES_MATCHING
            PATTERN "*.h"
        )
    ENDIF()

    IF(SSS_HAVE_HOST_LINUX_LIKE)
        INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    ENDIF(SSS_HAVE_HOST_LINUX_LIKE)
ENDIF(SSS_HAVE_HOSTCRYPTO_ANY)

IF(SSS_HAVE_HOSTCRYPTO_NONE)
    IF(UWBIOT_HOST_LINUX_LIKE)
        UWBIOT_INSTALL_LIBRARY(${PROJECT_NAME})
        INSTALL(
            DIRECTORY inc/ port/default/
            DESTINATION ${UWBIOT_INSTALL_INC_DIR}
            FILES_MATCHING
            PATTERN "*.h"
        )
    ENDIF(UWBIOT_HOST_LINUX_LIKE)
ENDIF(SSS_HAVE_HOSTCRYPTO_NONE)
