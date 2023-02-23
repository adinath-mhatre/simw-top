@echo off

@REM Copyright 2018,2019 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM

@REM
@REM Script to update the A71CH's keys and certificates.
@REM
@REM The demo examples expect these keys and certificates
@REM to be present in the A71CH
@REM
@REM The example applications generally reset the existing
@REM keys and certificates.
@REM

cd /d %~dp0

IF NOT EXIST ../ecc/tls_client.cer GOTO :NO_ECC_CERTIFICATES

IF "%~1" == "" GOTO :NO_PARAMS
    call ..\..\..\..\tools\A71CHConfig_vcom.exe %~1 script -f ResetAndUpdateA71CH.script.txt

goto :EOF
:NO_PARAMS
    echo Failed. Need to pass the COM Port as parameter to this file.
    echo Usage %~n0 ^<COM Port^>
    pause

goto :EOF
:NO_ECC_CERTIFICATES
    echo Failed. Can not continue.
    echo Run RunOnce_CreateCertificates.bat once to create certificates
    pause

