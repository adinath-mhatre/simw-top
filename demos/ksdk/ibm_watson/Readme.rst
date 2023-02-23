..
    Copyright 2019,2020 NXP



.. highlight:: bat

.. _ksdk-demos-ibm-watson:

==================================================
IBM Watson Demo for KSDK
==================================================

This demo demonstrates connection to IBM Watson IoT platform
using pre-provisioned device credentials and publish/subscribe
procedure using MQTT

Prerequisites
==================================================

- Active IBM Watson account
- MCUXpresso  installed (for running IBM demo on K64F)
- Any Serial communicator
- Flash VCOM binary on the device. VCOM binary can found under :file:`<PROJECT>\binaries\MCU` folder.
- Refer to :ref:`cli-tool` for ssscli tool setup
- Build Plug & Trust middleware stack. (Refer :ref:`building`)


Using WiFi with LPC55S
=======================================================================

WiFi shield CMWC1ZZABR-107-EVB by muRata is supported with LPCS55S. Mount the WiFi shield on to the
mikroBUS stackable headers.

.. _prepare-ibm-cloud:

Setting up IBM Watson IoT Platform
==================================================

1. Create an IBM ID which enables you to create an service instance for
   the Watson IoT platform (https://idaas.iam.ibm.com/idaas/mtfim/sps/authsvc?PolicyId=urn:ibm:security:authentication:asf:basicldapuser)

#.  Create an instance of Internet of Things Platform in the Watson IoT after logging in.
#.  Register the Root CA certificate (and Intermediate CA certificates if applicable) by following the below link
    https://console.bluemix.net/docs/services/IoT/reference/security/set_up_certificates.html#set_up_certificates

    i) Click on 'Launch' button to access to the IoT dashboard
    #) Click on 'Settings' tab
    #) Click on 'CA Certificates'
    #) Click on 'Add Certificate'
    #) A new pop-up appears. Click on 'Select a file' option and select the certificate
    #) Click on 'Save'

#.  Configure the security policies of the service by following steps

    i) Click on 'Security' tab
    #) Click on the pencil of 'Connection Security' to edit the preferences
    #) A new window is loaded, 'Connection Security'. In the Security Level field, select 'TLS with Client Certificate Authentication'.
    #) click on 'Save'

#.  Register Device type

    i) In the service, Click on 'Devices' tab and 'Device Types'
    #) Click on 'Add device type.
    #) Select the 'Device' type and write a name. Device type shall be registered
       as 'NXP-SE050-EC-D' and Optionally, add a description.
    #) Click 'Next'
    #) Optionally, add information to the rest of the fields.
       In this guide all the fields have been intentionally left empty. Finally, click 'Done'.
    #) For more information, refer to https://console.bluemix.net/docs/services/IoT/
       iotplatform_task.html#iotplatform_task

#.  Register device

    i) Click on 'Devices' tab.
    #) Click on 'Add Device'
    #) In the 'Identity' tab, select as 'Device Type' the one created in 'Register Device type' and
       the 'Device ID' the one retrieved using the pycli tool (UID of the device)
    #) Click on 'Next' button
    #) Click Done button to create the device

#.  Configure the application.

    i) In the 'watson_iot_config.h' file, update the org details in the macro
       "WATSONIOT_MQTT_BROKER_ENDPOINT" which we get from the URL of the dashboard
       https://org_id.internetofthings.ibmcloud.com/dashboard/#/overview
    #) update the org details and UID of the device in the macro 'WatsonechoCLIENT_ID'
       which is available in 'watson_iot_config.h'

#.  Configuring the publish application

    Create API key and authentication pair token

    i) In the Watson IoT Platform dashboard, go to Apps > API Keys.
    #) Click Generate API Key.

       .. note:: Important: Make a note of the API key and token pair. Authentication tokens are non-recoverable. If you lose or forget this token, you will need to re-register the API key to generate a new authentication token.

       An example of an API key is ``a-organization_id-a84ps90Ajs``

       An example of a token is ``MP$08VKz!8rXwnR-Q*``

    #) Add a comment to identify the API key in the dashboard, for example: Key to
       connect my application.
    #) Click Finish

Creating  and updating device keys and certificates to SE
===========================================================================

1) Complete :numref:`cli-doc-pre-steps` :ref:`cli-doc-pre-steps`

#) Check the vcom port number

#)  To create certificates on windows and provision, go to ``simw-top/pycli`` directory and call::

        call venv\Scripts\activate.bat
        cd Provisioning
        python GenerateIBMCredentials.py <COM_PORT>
        python ResetAndUpdate_IBM.py <COM_PORT>

    .. note::
        Provisioning of the keys is done with default policies.
        Refer - :numref:`cli-object-policy` to change the scripts to add required policies.

#) Certificates and Keys are generated at ``simw-top/pycli/Provisioning/ibm``



Building the Demo
=======================================================================
1) Open cmake project found under :file:`<SIMW-TOP>\projects` in MCUXPRESSO IDE

#) Update cmake options::
    - ``RTOS=FreeRTOS``
    - ``mbedTLS_ALT=SSS``

#) Update the build target in make file
    - Project:``cloud_ibm_watson``


Running the Demo
==================================================

1.  In the 'watson_iot_config.h' file, update the org details in the
    macro "WATSONIOT_MQTT_BROKER_ENDPOINT" which we get from the URL of the dashboard
    https://org_id.internetofthings.ibmcloud.com/dashboard/#/overview

#.  Update the org details and UID of the device in the macro 'WatsonechoCLIENT_ID' which is
    available in 'watson_iot_config.h'

#.  In OrgDetails.cfg file, update the Org details which we got from the previous step in the 'org' section

#.  In OrgDetails.cfg file, update the auth-key which we got from the
    above sections in to the 'auth-key' section

#.  Upate the UID of the device in the application test.py (at Line 40)

#.  Build the project and flash the binary on FRDM-K64F board

#.  Connect your board to open network

#.  Open a serial terminal on PC for OpenSDA serial device with these settings:
        - 115200 baud rate
        - 8 data bits
        - No parity
        - One stop bit
        - No flow control
        - change Setup-->Terminal-->New-line-->Receive-->AUTO

#.  Press reset button on the board

#.  To see the event coming in to device and event going out of the device, login to
    the Watson IoT platform and launch the service:
    i) Click 'Devices'
    #) Click the registered device id
    #) Click 'Recent Events'
    #) Events will be displayed in portal

#.  Persistent RED LED ON indicates error
#.  All lights off along with the following message indicates readiness to
    subscribe messages fromAWS::

        Subscribing...
        -->sleep
        -->sleep
        Publish done


#.  Run the Publish application to publish events to the device.

    To do that, run::

        python test.py OrgDetails.cfg GREEN ON

    The above command ensures that the green LED is turned ON. Similarly RED and BLUE LED can be turned ON and OFF

#.  Events that are published shall be verified in the Watson Platform Dashboard(Refer to section 15)


Appendix
==================================================

1. For more information, refer to https://cloud.ibm.com/docs/services/IoT?topic=iot-platform-about_iotplatform
