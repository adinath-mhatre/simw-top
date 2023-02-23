/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <stdio.h>

#include "ex_a71ch_keystore.h"

static ex_sss_boot_ctx_t gex_sss_a71ch_keystore;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_a71ch_keystore)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint32_t extKeyId = COMMON_KEY_ID;
    uint8_t data[32] = {0};
    size_t dataLen = sizeof(data);
    size_t keybitlen = dataLen * 8;
    sss_object_t object;

    sss_status = sss_key_object_init(&object, &gex_sss_a71ch_keystore.ks);

    sss_status = sss_key_object_get_handle(&object, extKeyId);

    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Get handle Failed");
        goto cleanup;
    }

    sss_status = sss_key_store_get_key(&gex_sss_a71ch_keystore.ks, &object, data, &dataLen, &keybitlen);

    if (sss_status != kStatus_SSS_Success) {
        LOG_E("Get key Failed");
        goto cleanup;
    }

    sss_status = sss_key_store_save(&pCtx->ks);
    LOG_I("Passed\n");
cleanup:
    return sss_status;
}
