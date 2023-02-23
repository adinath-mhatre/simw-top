Here you find precompiled binaries for Windows/linux and supported MCU platforms:

Windows example binaries compiled with VCOM interface to be executed on windows using a MCU with vcom firmware as interface (like below se05x_vcom-T1oI2C-frdmk64f.bin):
./PCWindows/VCOM-se050_GetInfo.exe (Provides version info and identification of the IC)
./PCWindows/VCOM-se051_GetInfo.exe (Provides version info and identification of the IC)
./PCWindows/VCOM-None-se050_Delete_and_test_provision.exe (Use delete to delete user objects - NXP certificates preserved)
./PCWindows/VCOM-None-se051_Delete_and_test_provision.exe (Use delete to delete user objects - NXP certificates preserved)
./PCWindows/VCOM-sems_lite_cli_app.exe (command line client for applet updates on SE051 using SEMS Lite applet)
./PCWindows/VCOM-se051_Personalization.exe (command line client for PERSO applet)

Examples like above, but using PlatfromSCP authentication with SE050/51 default keys:
./PCWindows/VCOM-PlatfSCP03-se050_Delete_and_test_provision.exe
./PCWindows/VCOM-PlatfSCP03-se051_Delete_and_test_provision.exe

PCWindows binaries sss command line interface and Cloud Provisioning data creation compiled for VCOM interface
./PCWindows/ssscli/ssscli.exe (command line client to communicate with SE05x)
./PCWindows/ssscli/Provision_AWS.exe (Generate and provision AWS credentials)
./PCWindows/ssscli/Provision_AZURE.exe (Generate and provision Azure credentials)
./PCWindows/ssscli/Provision_GCP.exe (Generate and provision GCP credentials)
./PCWindows/ssscli/Provision_IBM.exe (Generate and provision IBM Watson credentials)
./PCWindows/ssscli/[libraries]

The MCU firmware binaries "vcom*" provide a VCOM port for communication to the secure element to let the Windows examples connect over VCOM to the secure element.
The MCU firmware binaries "ccid*" provide a CCID reader emulation to the secure element for software which is using e.g. PC/SC smartcard interface

MCU binaries for SE050/51 using UM11225 T=1oI2C protocol:
./MCU/se05x/se05x_ccid-T1oI2C-frdmk64f.bin (CCID interface for K64F)
./MCU/se05x/se05x_vcom-T1oI2C-evkmimxrt1060.bin (VCOM interface for i.MX RT1060)
./MCU/se05x/se05x_vcom-T1oI2C-frdmk64f.bin (VCOM interface for K64F)
./MCU/se05x/se05x_vcom-T1oI2C-lpcxpresso55s69.bin (VCOM interface for LPC55S69 EVK)
./MCU/se05x/se050_GetInfo-T1oI2C-frdmk64f.bin (GetInfo example for direct execution on the MCU)
./MCU/se05x/se051_GetInfo-T1oI2C-frdmk64f.bin (GetInfo example for direct execution on the MCU)
./MCU/se05x/se050_GetInfo-T1oI2C-evkmimxrt1060 (GetInfo example for direct execution on the MCU)
./MCU/se05x/se051_GetInfo-T1oI2C-evkmimxrt1060 (GetInfo example for direct execution on the MCU)

MCU binaries for SE051 using Global Platform T=1oI2C protocol:
./MCU/SE05x/se05x_ccid-T1oI2C_GP1_0-frdmk64f.bin
./MCU/SE05x/se05x_vcom-T1oI2C_GP1_0-evkmimxrt1060.bin
./MCU/SE05x/se05x_vcom-T1oI2C_GP1_0-frdmk64f.bin
./MCU/se05x/se051_GetInfo-T1oI2C_GP1_0-frdmk64f.bin (GetInfo example for direct execution on the MCU)
./MCU/se05x/se051_GetInfo-T1oI2C_GP1_0-evkmimxrt1060.bin (GetInfo example for direct execution on the MCU)

MCU binaries for A71CH using SCI2C protocol (VCOM and CCID interface) like for SE05x:
./MCU/a71xx/a71xx_ccid-SCI2C-frdmk64f-A71XX.bin
./MCU/a71xx/a71xx_vcom-SCI2C-evkmimxrt1060-A71XX.bin
./MCU/a71xx/a71xx_vcom-SCI2C-frdmk64f-A71XX.bin
