/* Copyright 2021-2022 NXP
 *
 * NXP Confidential. This software is owned or controlled by NXP and may only
 * be used strictly in accordance with the applicable license terms.  By
 * expressly accepting such terms or by downloading, installing, activating
 * and/or otherwise using the software, you are agreeing that you have read,
 * and that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you may
 * not retain, install, activate or otherwise use the software.
 */

/* This is an auto generated file */

#include "sems_lite_api.h"
#include "Update_NXP_SE051_IoT_A564_Applet_7.2.h"
/* doc:start:SEMS-Lite-protobuf-declare */

static const uint8_t aid_1[] = M_subComponent_1_aid;

static const sub_component_metaData_t subcomponent_1 = {
	.nameLen = \
		M_subComponent_1_nameLen,
	.pName = \
		M_subComponent_1_szName,
	.aidLen = \
		M_subComponent_1_aidLen,
	.pAid = \
		aid_1,
	.version = \
		M_subComponent_1_version,
	.minimumPreviousVersion = \
		M_subComponent_1_minimumPreviousVersion,
	.pNextSubComponentMetaData = \
		NULL,
};

static const uint8_t cmd_signature[] = M_signatureOverCommands;

static const uint8_t commands[] = M_multicastCommands;

const multicast_package_t multicast_package = {
	.semsLiteAPIVersion = \
		M_semsLiteAPIVersion,
	.targetEntityID = \
		M_targetEntityID,
	.target12Nc = \
		M_target12Nc,
	.requiredFreeBytesNonVolatileMemory = \
		M_requiredFreeBytesNonVolatileMemory,
	.requiredFreeBytesTransientMemory = \
		M_requiredFreeBytesTransientMemory,
	.multicastPackageNameLen = \
		M_multicastPackageNameLen,
	.pMulticastPackageName = \
		M_szMulticastPackageName,
	.multicastPackageVersion = \
		M_multicastPackageVersion,
	.pSubComponentMetaData = \
		&subcomponent_1,
	.signatureOverCommandsLen = \
		M_signatureOverCommandsLen,
	.pSignatureOverCommands = \
		cmd_signature,
	.multicastCommandsLen = \
		M_multicastCommandsLen,
	.pMulticastCommands = \
		commands,
};

/* doc:end:SEMS-Lite-protobuf-declare */
