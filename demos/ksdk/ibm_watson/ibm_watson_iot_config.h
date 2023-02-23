/**
 * @file watson_iot_config.h.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * IBM watson demo config file
 */

#ifndef WATSON_IOT_CONFIG
#define WATSON_IOT_CONFIG

/*The org details leohx6 which is mentioned below is obtained when we create a IBM Cloud account. Please replace
 * the Org details which is relevant the Organisation
 * ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
 * */
/* doc:start:watson-broker-endpoint */
#define WATSONIOT_MQTT_BROKER_ENDPOINT "leohx6.messaging.internetofthings.ibmcloud.com"
/* doc:end:watson-broker-endpoint */

#define WATSONIOT_MQTT_BROKER_PORT 8883 ///< default port for MQTT/S

/* doc:start:watson-client-id */
#define WatsonechoCLIENT_ID \
    "d:leohx6:NXP-SE050-EC-D:377813914287991534125055" ///< MQTT client ID should be unique for every device
/* doc:end:watson-client-id */

#define WATSONIOT_A71CH_CLIENT_ID ((const uint8_t *)WatsonechoCLIENT_ID)

#define WATSON_IOT_KEYS_INDEX_SM 0 ///< Index where client key is kept

/* doc:start:watson-key-ids */
#define SSS_KEYPAIR_INDEX_CLIENT_PRIVATE 0x20181003 //keyID of device keypair
#define SSS_CERTIFICATE_INDEX 0x20181004            //keyID of device certificate
/* doc:end:watson-key-ids */

/*Subscribe for all the topics*/
#define WATSON_SUB_TOPIC "iot-2/cmd/+/fmt/+"

/*Publication topic is json*/
#define WATSON_PUB_TOPIC "iot-2/evt/status/fmt/json"

/*User Name to be used during MQTT connect*/
#define CUSTOM_MQTT_USER_NAME "use-token-auth"

static unsigned char tlsVERISIGN_ROOT_CERT_WATSON_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
    "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
    "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n"
    "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n"
    "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n"
    "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n"
    "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n"
    "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n"
    "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n"
    "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n"
    "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n"
    "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n"
    "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n"
    "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n"
    "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\n"
    "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n"
    "-----END CERTIFICATE-----\n";

static const uint32_t tlsVERISIGN_ROOT_CERT_WATSON_LENGTH = sizeof(tlsVERISIGN_ROOT_CERT_WATSON_PEM);

#endif /* WATSON_IOT_CONFIG */
