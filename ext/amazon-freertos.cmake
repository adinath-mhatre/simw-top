# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

SET(DEMOS_KSDK_DIR ${SIMW_TOP_DIR}/demos/ksdk)

PROJECT(freertos-kernel)

FILE(
    GLOB
    files
    amazon-freertos/freertos_kernel/*.c
    amazon-freertos/libraries/logging/iot_logging.c
    amazon-freertos.cmake
)

LIST(
    APPEND
    files
    amazon-freertos/libraries/logging/iot_logging_task_dynamic_buffers.c
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
        port_files
        ${SIMW_TOP_DIR}/demos/ksdk/common/amazon-freertos/lib/FreeRTOS/portable/MSVC-MingW/*.c
        amazon-freertos/freertos_kernel/portable/MemMang/heap_4.c
        ${DEMOS_KSDK_DIR}/x86pc/*.h
        # amazon-freertos/libraries/3rdparty/tracealyzer_recorder/Include/*.h
        amazon-freertos/libraries/3rdparty/tracealyzer_recorder/*.c
        amazon-freertos/lib/include/private/*.h
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F)
    FILE(
        GLOB
        port_files
        amazon-freertos/freertos_kernel/portable/GCC/ARM_CM4F/*.c
        amazon-freertos/freertos_kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
        GLOB
        port_files
        amazon-freertos/freertos_kernel/portable/GCC/ARM_CM4F/*.c
        amazon-freertos/freertos_kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        port_files
        amazon-freertos/freertos_kernel/portable/GCC/ARM_CM33_NTZ/non_secure/*.c
        amazon-freertos/freertos_kernel/portable/MemMang/heap_4.c
        ${SIMW_TOP_DIR}/demos/ksdk/common/freertos/*.c
    )
ENDIF()

IF(
    SSS_HAVE_APPLET_A7XX
    OR SSS_HAVE_APPLET_SE050_EAR
    OR SSS_HAVE_APPLET_SE05X_IOT
    OR SSS_HAVE_APPLET_LOOPBACK
)
    LIST(
        APPEND
        port_files
        ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra/sm_demo_utils_rtos.c
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} ${files} ${port_files})

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC amazon-freertos/freertos_kernel/include
    #PUBLIC amazon-freertos/lib/include/private
    PUBLIC amazon-freertos/libraries/abstractions/wifi/include
    PUBLIC ${SIMW_TOP_DIR}/sss/ex/inc
    PUBLIC ${DEMOS_KSDK_DIR}/common
    PUBLIC amazon-freertos/libraries/abstractions/platform/freertos/include
    PUBLIC amazon-freertos/libraries/abstractions/platform/include
    PUBLIC amazon-freertos/libraries/c_sdk/standard/common/include
    PUBLIC amazon-freertos/libraries/logging/include
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${DEMOS_KSDK_DIR}/x86pc
        PUBLIC amazon-freertos/libraries/3rdparty/tracealyzer_recorder/Include
        PUBLIC ${SIMW_TOP_DIR}/demos/ksdk/common/amazon-freertos/lib/FreeRTOS/portable/MSVC-MingW/
    )
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC amazon-freertos/freertos_kernel/portable/GCC/ARM_CM4F)
ENDIF()

IF(SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC amazon-freertos/freertos_kernel/portable/GCC/ARM_CM4F)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME} PUBLIC amazon-freertos/freertos_kernel/portable/GCC/ARM_CM33_NTZ/non_secure
    )
ENDIF()

ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)


IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4127 # conditional expression is constant
    )
ENDIF()


#IF(SSS_HAVE_HOST_LPCXPRESSO55S)
#  MESSAGE("No FreeRTOS IP")
#ELSE()

PROJECT(freertos-ip)

FILE(
    GLOB
    files
    #amazon-freertos/lib/bufferpool/aws_bufferpool_static_thread_safe.c
    amazon-freertos/libraries/freertos_plus/standard/crypto/src/iot_crypto.c
    #amazon-freertos/lib/crypto/*.c
    #amazon-freertos/lib/FreeRTOS-Plus-TCP/source/*.c
    amazon-freertos/libraries/freertos_plus/standard/freertos_plus_tcp/portable/BufferManagement/BufferAllocation_2.c
    #amazon-freertos/lib/FreeRTOS-Plus-TCP/source/portable/BufferManagement/BufferAllocation_2.c
    #amazon-freertos/lib/mqtt/*.c
    amazon-freertos/libraries/3rdparty/jsmn/*.c
    amazon-freertos/libraries/freertos_plus/standard/tls/src/iot_tls.c
    amazon-freertos/libraries/abstractions/pkcs11/corePKCS11/source/core_pkcs11.c
    #amazon-freertos/lib/tls/*.c
    amazon-freertos/libraries/freertos_plus/standard/utils/src/iot_system_init.c
    #amazon-freertos/lib/utils/aws_system_init.c
    #amazon-freertos/libraries/abstractions/secure_sockets/lwip/iot_secure_sockets.c
    amazon-freertos/libraries/c_sdk/standard/common/iot_init.c
    amazon-freertos/libraries/c_sdk/standard/common/iot_device_metrics.c
    amazon-freertos/libraries/c_sdk/standard/mqtt/src/*.c
    amazon-freertos/libraries/coreMQTT/source/*.c
    amazon-freertos/libraries/c_sdk/standard/common/taskpool/*.c
    amazon-freertos/libraries/abstractions/platform/freertos/*.c
    amazon-freertos/libraries/abstractions/pkcs11/corePKCS11/source/core_pki_utils.c
    amazon-freertos/libraries/3rdparty/mbedtls_utils/*.c
    amazon-freertos.cmake
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    FILE(
        GLOB
        port_files
        # amazon-freertos/lib/secure_sockets/portable/pc/windows/aws_secure_
        # sockets.c
        # amazon-freertos/lib/pkcs11/mbedtls/aws_pkcs11_mbedtls.c
        ${DEMOS_KSDK_DIR}/x86pc/*.h
        # ${DEMOS_KSDK_DIR}/x86pc/aws_demo_logging.c
        ${DEMOS_KSDK_DIR}/x86pc/aws_run-time-stats-utils.c
        ${DEMOS_KSDK_DIR}/x86pc/aws_entropy_hardware_poll.c
        ${DEMOS_KSDK_DIR}/x86pc/application_utils.c
        ${DEMOS_KSDK_DIR}/x86pc/win_pcap/*.h
        ${SIMW_TOP_DIR}/demos/ksdk/common/amazon-freertos/lib/FreeRTOS-Plus-TCP/Source/portable/Compiler/MSVC/*.h
        ${SIMW_TOP_DIR}/demos/ksdk/common/amazon-freertos/lib/FreeRTOS-Plus-TCP/source/portable/NetworkInterface/WinPCap/NetworkInterface.c
        # amazon-freertos/lib/pkcs11/portable/pc/windows/*.c
        amazon-freertos/libraries/abstractions/secure_sockets/freertos_plus_tcp/iot_secure_sockets.c
        amazon-freertos/libraries/freertos_plus/standard/freertos_plus_tcp/*.c
        # amazon-freertos/lib/secure_sockets/portable/freertos_plus_tcp/*.c
        # amazon-freertos/lib/third_party/tracealyzer_recorder/*.c
    )
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS AND ENABLE_CLOUD_DEMOS AND SSS_HAVE_MBEDTLS_ALT)
    LIST(
        APPEND
        port_files
        ${DEMOS_KSDK_DIR}/x86pc/main.c
    )
ENDIF()

IF(SSS_HAVE_KSDK)

    IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S)
        FILE(
            GLOB
            port_files
            mcu-sdk/middleware/lwip/src/api/*.c
            #amazon-freertos/libraries/abstractions/secure_sockets/lwip/iot_secure_sockets.c
            #amazon-freertos/lib/secure_sockets/portable/nxp/lwip/*.c
            amazon-freertos/vendors/nxp/secure_sockets/lwip/iot_secure_sockets.c
            mcu-sdk/middleware/lwip/src/core/*.c
            mcu-sdk/middleware/lwip/src/core/ipv4/*.c
            mcu-sdk/middleware/lwip/src/api/*.c
            mcu-sdk/middleware/lwip/src/netif/ethernet.c
            mcu-sdk/middleware/lwip/port/enet_ethernetif.c
            mcu-sdk/middleware/lwip/port/enet_ethernetif_kinetis.c
            mcu-sdk/middleware/lwip/port/sys_arch.c
            mcu-sdk/devices/${KSDK_CPUName}/drivers/fsl_enet.c
        )
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        port_files
        amazon-freertos/vendors/nxp/wifi/serial_mwm/iot_wifi.c
        amazon-freertos/vendors/nxp/secure_sockets/serial_mwm/iot_secure_sockets.c
    )
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT)
    FILE(
        GLOB
        alt_files
        ${SIMW_TOP_DIR}/sss/plugin/pkcs11/*.c
        #amazon-freertos/lib/pkcs11/portable/nxp/se_hostlib/*.c
    )
ENDIF()

ADD_LIBRARY(
    ${PROJECT_NAME}
    ${files}
    ${port_files}
    ${alt_files}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE amazon-freertos/libraries/abstractions/pkcs11/corePKCS11/source/include
    PRIVATE amazon-freertos/libraries/3rdparty/pkcs11
    # PRIVATE amazon-freertos/lib/third_party/pkcs11
    PUBLIC amazon-freertos/libraries/freertos_plus/standard/freertos_plus_tcp/include
    #PUBLIC amazon-freertos/lib/FreeRTOS-Plus-TCP/include
    #PUBLIC amazon-freertos/lib/FreeRTOS-Plus-TCP/Source/portable/BufferManagement
    PUBLIC amazon-freertos/libraries/3rdparty/jsmn
    PRIVATE amazon-freertos/libraries/freertos_plus/standard/crypto/include
    # PRIVATE amazon-freertos/libraries/abstractions/pkcs11/mbedtls
    PRIVATE amazon-freertos/libraries/3rdparty/mbedtls_config
    PRIVATE amazon-freertos/libraries/freertos_plus/standard/tls/include
    PRIVATE amazon-freertos/libraries/freertos_plus/standard/pkcs11/include
    PRIVATE amazon-freertos/demos/include
    PUBLIC amazon-freertos/libraries/c_sdk/standard/common/include/private
    PRIVATE amazon-freertos/libraries/freertos_plus/standard/utils/include
    PUBLIC amazon-freertos/libraries/abstractions/secure_sockets/include
    PUBLIC amazon-freertos/libraries/c_sdk/standard/common/include
    PUBLIC amazon-freertos/libraries/abstractions/platform/freertos/include
    PUBLIC amazon-freertos/libraries/c_sdk/standard/mqtt/include
    PUBLIC amazon-freertos/libraries/coreMQTT/source/include
    PRIVATE amazon-freertos/libraries/coreMQTT/source/interface
    PUBLIC amazon-freertos/libraries/abstractions/platform/include
    PRIVATE amazon-freertos/libraries/3rdparty/mbedtls_utils
)

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC ${DEMOS_KSDK_DIR}/x86pc
        PUBLIC ${DEMOS_KSDK_DIR}/common
        PUBLIC amazon-freertos/libraries/3rdparty/win_pcap
        # PUBLIC amazon-freertos/lib/third_party/win_pcap
        PUBLIC ${SIMW_TOP_DIR}/demos/ksdk/common/amazon-freertos/lib/FreeRTOS-Plus-TCP/Source/portable/Compiler/MSVC
    )
ENDIF()

IF(SSS_HAVE_MBEDTLS_ALT)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        #PUBLIC amazon-freertos/lib/pkcs11/portable/nxp/se_hostlib/
        #PUBLIC amazon-freertos/lib/third_party/mcu_vendor/nxp/mflash/se_hostlib
        PUBLIC ../sss/ex/inc
        PUBLIC ${SIMW_TOP_DIR}/sss/plugin/pkcs11
    )
ENDIF()

IF(SSS_HAVE_KSDK)
    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PUBLIC amazon-freertos/libraries/freertos_plus/standard/freertos_plus_tcp/portable/Compiler/GCC
        #PUBLIC amazon-freertos/lib/FreeRTOS-Plus-TCP/source/portable/Compiler/GCC
        PUBLIC ../demos/ksdk/common
        PUBLIC ../demos/ksdk/gcp
        #PUBLIC amazon-freertos/lib/pkcs11/portable/nxp/se_hostlib
        PUBLIC ../mcu-sdk/middleware/lwip/src/include
    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${DEMOS_KSDK_DIR}/common)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    mbedtls
    freertos-kernel
    ex_common
)

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} wifi_serial_mwm)
ENDIF()

IF(SSS_HAVE_APPLET_A7XX OR SSS_HAVE_APPLET_SE050_EAR)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} wpcap)
ENDIF()

#ENDIF() #FreeRTOS IP

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=unused-variable
        PRIVATE -Wno-unused-variable
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-unused-function
        PRIVATE -Wno-array-bounds
    )
    SIMW_DISABLE_EXTRA_WARNINGS(${PROJECT_NAME})

ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE
            /wd4310 # cast truncates constant value
            /wd4127 # conditional expression is constant
            /wd4189 # local variable is initialized but not referenced
            /wd4005 # macro redefinition
            /wd4456 # hides previous local declaration
            /wd4101 # unreferenced local variable
            /wd4267 # possible loss of data
            /wd4295 # array is too small to include a terminating null character
            /wd4057 # differs in indirection to slightly different base types
            /wd4200 # nonstandard extension used: zero-sized array in struct/union
            /wd4055 # type cast: from data pointer to function pointer
            /wd4701 # potentially uninitialized local variable
    )
ENDIF()
