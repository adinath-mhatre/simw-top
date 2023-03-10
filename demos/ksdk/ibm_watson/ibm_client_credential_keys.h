/*
 *
 * Copyright 2018,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IBM_CREDENTIAL_KEYS_H
#define IBM_CREDENTIAL_KEYS_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !SSS_HAVE_IBM
#error Only with IBM_IOT
#endif

#ifdef __GNUC__
#define USED __attribute__((used))
#else
#define USED
#endif
/*
 * Not Used for se_hostlib
 */

static const char keyCLIENT_CERTIFICATE_PEM[] = {0};

/*
 */
static const char USED *keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM = NULL;

/*
 * Not Used for se_hostlib
 */
static const char keyCLIENT_PRIVATE_KEY_PEM[] = {0};

#endif
