#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

IF(SSS_HAVE_APPLET_A71CH_SIM AND NXPInternal)
    IF(
        "${SCP}"
        STREQUAL
        "SCP03_HostCrypto"
    )

    ENDIF()
ENDIF()

IF(
    SSS_HAVE_APPLET_LOOPBACK
    AND SSS_HAVE_HOST_FRDMK64F
    AND NXPInternal
)
    ADD_SUBDIRECTORY(WithApplet_LoopBack_use)
ENDIF()
