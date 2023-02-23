#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

ADD_SUBDIRECTORY(hostLib)

# ADD_SUBDIRECTORY(hostlib/a71cl/tst)
#
# ADD_SUBDIRECTORY(hostlib/a71cl/ex_hlse)
#

IF(SSS_HAVE_APPLET_A71CH OR SSS_HAVE_APPLET_A71CH_SIM)
    IF(SSS_HAVE_RTOS_DEFAULT)
        ADD_SUBDIRECTORY(useCase)
    ENDIF()
ENDIF()
