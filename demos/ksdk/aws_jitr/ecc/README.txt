This folder contains certificates for AWS Demo.

Execute ..\scripts\RunOnce_CreateCertificates.bat to create 
certificates in this folder


Scripts to generate ECC Certificates for A71CH Customer Programmable 
sample and connect to AWS Cloud as described in 
https://aws.amazon.com/blogs/iot/just-in-time-registration-of-device-certificates-on-aws-iot/

Pre-Requisites: 
	- Customer Programmable A71CH Sample
    - A71CH Config tool and VCOM Based connection to A71CH (Freedom-K64F)
	- AWS Account
	- "Registration code" from AWS As listed shown in "Step 2: Copy this registration code" of "Register a CA certificate"
      https://eu-central-1.console.aws.amazon.com/iot/home?region=eu-central-1#/cacertificatehub

After running this script:
	- Upload to the cloud rootCA.pm and verificationCert.crt
	- Ensure "Activate CA certificate" and "Enable auto-registration of device certificates" are checked/enabled.
	
After running the Demo:
	- One time *Actvation of device certificate is needed". When doing this manually, activate via web interface of AWS Cloud.
