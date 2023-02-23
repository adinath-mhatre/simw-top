/* Copyright 2019,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* TO BE Run only under PlatfromSCP*/

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <string.h>

#include "ex_sss_auth.h"
#include "smCom.h"

/* clang-format off */
#define MandateSCP_UserID_VALUE                 \
    {                                           \
        'N', 'E', 'E', 'D', 'S', 'C', 'P'            \
    }
/* clang-format ON */

static ex_sss_boot_ctx_t gex_sss_mandate_scp_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_mandate_scp_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for Plug & Trust  */
/* MW examples which will call ex_sss_entry()                                 */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status;
    sss_session_t reEnableSession = { 0 };
    sss_tunnel_t reEnableTunnel = { 0 };
    SE_Connect_Ctx_t eraseAuthCtx = { 0 };

    smStatus_t sw_status;
    Se05xSession_t *pSe05xSession;
    sss_object_t ex_id = { 0 };

    const uint8_t host_userid_value[] = MandateSCP_UserID_VALUE;
    eraseAuthCtx.auth.ctx.idobj.pObj = &ex_id;

    /* Prepare host */

    status = sss_key_object_init(eraseAuthCtx.auth.ctx.idobj.pObj, &pCtx->host_ks);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed sss_key_object_init");
        goto cleanup;
    }
    status = sss_key_object_allocate_handle(eraseAuthCtx.auth.ctx.idobj.pObj,
                                            MAKE_TEST_ID(__LINE__),
                                            kSSS_KeyPart_Default,
                                            kSSS_CipherType_UserID,
                                            sizeof(host_userid_value),
                                            kKeyObject_Mode_Transient);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed sss_key_object_allocate_handle");
        goto cleanup;
    }
    status = sss_key_store_set_key(&pCtx->host_ks,
                                   eraseAuthCtx.auth.ctx.idobj.pObj,
                                   host_userid_value,
                                   sizeof(host_userid_value),
                                   sizeof(host_userid_value) * 8,
                                   NULL,
                                   0);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed sss_key_store_set_key");
        goto cleanup;
    }

    pSe05xSession = &((sss_se05x_session_t *)&reEnableSession)->s_ctx;
    eraseAuthCtx.tunnelCtx = &reEnableTunnel;
    reEnableTunnel.session = &pCtx->session;
    eraseAuthCtx.connType = kType_SE_Conn_Type_Channel; // pOpenCtx->connType;
    eraseAuthCtx.portName = NULL; // pOpenCtx->portName;
    eraseAuthCtx.auth.authType = kSSS_AuthType_ID;


    status = sss_session_open(&reEnableSession, kType_SSS_SE_SE05x,
                               kSE05x_AppletResID_PLATFORM_SCP,
            kSSS_ConnectionType_Password, &eraseAuthCtx);

    if (kStatus_SSS_Success != status) {
        LOG_E("Failed sss_session_open");
        goto cleanup;
    }

    /* Call SE05X API to Mandate Platform SCP. */

    sw_status = Se05x_API_SetPlatformSCPRequest(pSe05xSession, kSE05x_PlatformSCPRequest_NOT_REQUIRED);
    if(SM_OK != sw_status) {
        LOG_E("Se05x_API_SetPlatformSCPRequest Failed");
        goto cleanup;
    }
    else {
        LOG_I("Se05x_API_SetPlatformSCPRequest Successful");
        LOG_W("Further communication must not be encrypted");
    }

cleanup:
    return status;
}
