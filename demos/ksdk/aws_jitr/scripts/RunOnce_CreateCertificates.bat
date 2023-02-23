
SETLOCAL

@REM Copyright 2018 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM

@REM
@REM Script to create credentials for AWS JITR Demo
@REM
@REM See README in ..\ecc folder for more information.
@REM


@cd /d %~dp0..\..\..

@SET PATH=%PATH%;%CD%\tools;%CD%\ext\openssl\bin

@SET OPENSSL_EXE=call openssl.exe
@SET OPENSSL_CONFIG=-config %CD%\ext\openssl\ssl\openssl.cnf
cd /d %~dp0

@SET rootca=..\ecc\tls_rootca

@SET client_key=..\ecc\tls_client_key.pem
@SET client_key_pub=..\ecc\tls_client_key_pub.pem
@REM  Contains public key only
@SET client_csr=..\ecc\tls_client.csr
@SET client_cer=..\ecc\tls_client.cer

@SET rootca_srl=%rootca%.srl

@SET ecc_param_pem=..\ecc\prime256v1.pem

IF EXIST %rootca_srl% (
    @echo ">> %rootca_srl% already exists, use it"
    @SET x509_serial=-CAserial %rootca_srl%
) ELSE (
    @echo ">> no %rootca_srl% found, create it"
    @SET x509_serial=-CAserial %rootca_srl% -CAcreateserial
)

@echo "Prepare ECC TLS credentials (Client side material)"

IF NOT EXIST %ecc_param_pem% (
    @echo "Creating ECC parameter file: %ecc_param_pem% for prime256v1"
    %OPENSSL_EXE% ecparam -name prime256v1 -out %ecc_param_pem%
) ELSE (
    @echo "ECC parameter file %ecc_param_pem% already exists"
)

IF NOT EXIST ..\ecc\verificationCert.key (
	%OPENSSL_EXE% genrsa -out ..\ecc\verificationCert.key 2048
)

IF NOT EXIST ..\ecc\verificationCert.csr (
	@echo Follow steps from Amazon website to create an intermediate CA.
	%OPENSSL_EXE% req -new -key ..\ecc\verificationCert.key -out ..\ecc\verificationCert.csr %OPENSSL_CONFIG%
)

@REM  Conditionally create CA
IF NOT EXIST %rootca%_key.pem (
    @echo ">> Creating new RootCA key (%rootca%_key.pem) and RootCA certificate (%rootca%.cer)"
    %OPENSSL_EXE% ecparam -in %ecc_param_pem% -genkey -out %rootca%_key.pem
    %OPENSSL_EXE% ec -in %rootca%_key.pem -text -noout
    %OPENSSL_EXE% ec -in %rootca%_key.pem -outform DER -out %rootca%_key.der
) ELSE (
    @echo ">> RootCA key (%rootca%_key.pem) already exist"
)

IF NOT EXIST %rootca%_pub_key.pem (
	%OPENSSL_EXE% ec -in %rootca%_key.pem -pubout -out %rootca%_pub_key.pem
)

IF NOT EXIST %rootca%.cer (
    @echo ">> Creating new - selfsigned - RootCA (%rootca%.cer) certificate"
    %OPENSSL_EXE% req -x509 -new -nodes -key %rootca%_key.pem ^
        -subj "/C=BE/ST=VlaamsBrabant/L=Leuven/O=NXP-Demo-CA/OU=Demo-Unit/CN=demoCA/emailAddress=demoCA@nxp" ^
        -days 2800 -out %rootca%.cer %OPENSSL_CONFIG%
    %OPENSSL_EXE% x509 -in %rootca%.cer -text -noout
) ELSE (
    @echo ">> RootCA certificate (%rootca%.cer) already exist"
)

IF NOT EXIST ..\ecc\verificationCert.crt (
	%OPENSSL_EXE% x509 -req -in ..\ecc\verificationCert.csr -CA %rootca%.cer -CAkey %rootca%_key.pem -CAcreateserial -out ..\ecc\verificationCert.crt -days 500 -sha256
)
copy /y %rootca%.cer ..\ecc\rootCA.pem

@REM  Conditionally create client key
IF NOT EXIST %client_key% (
    @echo ">> Creating client key: %client_key%"
    %OPENSSL_EXE% ecparam -in %ecc_param_pem% -genkey -out %client_key%
    %OPENSSL_EXE% ec -in %client_key% -text -noout
) ELSE (
    @echo ">> %client_key% already exists"
)

@REM  Create a client key pem file containing ONLY the public key
@echo ">> Creating client key with public key only; typically used by verifier: %client_key_pub%"
%OPENSSL_EXE% ec -in %client_key% -pubout -out %client_key_pub%

@echo ">> Now create CSR"
%OPENSSL_EXE% req -new -key %client_key% -subj "/C=BE/O=NXPDemo/OU=Unit/CN=localhost" -out %client_csr% %OPENSSL_CONFIG%
%OPENSSL_EXE% req -in %client_csr% -text %OPENSSL_CONFIG%

@REM  Always create a CA signed client certificate
%OPENSSL_EXE% x509 -req -sha256 -days 2800 -in %client_csr% %x509_serial% -CA %rootca%.cer -CAkey %rootca%_key.pem -out %client_cer%
%OPENSSL_EXE% x509 -in %client_cer% -text -noout

@echo ">> Client certificate and key available for use"
@echo ">> ********************************************"

:END

ENDLOCAL
