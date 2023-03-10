/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_DEVICE_DESCRIPTOR_H__
#define __USB_DEVICE_DESCRIPTOR_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_DEVICE_SPECIFIC_BCD_VERSION (0x0200U)
#define USB_DEVICE_DEMO_BCD_VERSION (0x0101U)

#define USB_DEVICE_CLASS (0x00U)
#define USB_DEVICE_SUBCLASS (0x00U)
#define USB_DEVICE_PROTOCOL (0x00U)

#define USB_DEVICE_MAX_POWER (0x32U)

#define USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL (sizeof(g_UsbDeviceConfigurationDescriptor))
#define USB_DESCRIPTOR_LENGTH_STRING0 (sizeof(g_UsbDeviceString0))
#define USB_DESCRIPTOR_LENGTH_STRING1 (sizeof(g_UsbDeviceString1))
#define USB_DESCRIPTOR_LENGTH_STRING2 (sizeof(g_UsbDeviceString2))
#define USB_DESCRIPTOR_LENGTH_STRING3 (sizeof(g_UsbDeviceString3))

#define USB_DEVICE_CONFIGURATION_COUNT (1U)
#define USB_DEVICE_STRING_COUNT (4U)
#define USB_DEVICE_LANGUAGE_COUNT (1U)

#define USB_DEVICE_CCID_CLASS (0x0BU)
#define USB_DEVICE_CCID_SUBCLASS (0x00U)
#define USB_DEVICE_CCID_PROTOCOL (0x00U)

#define USB_DEVICE_CCID_SMART_CARD_CONFIGURE_INDEX (1U)

#define USB_DEVICE_CCID_SMART_CARD_INTERFACE_COUNT (1U)
#define USB_DEVICE_CCID_SMART_CARD_INTERFACE_INDEX (0U)
#define USB_DEVICE_CCID_SMART_CARD_ENDPOINT_COUNT (3U)
#define USB_DEVICE_CCID_SMART_CARD_ENDPOINT_BULK_IN (1U)
#define USB_DEVICE_CCID_SMART_CARD_ENDPOINT_BULK_OUT (2U)
#define USB_DEVICE_CCID_SMART_CARD_ENDPOINT_INTERRUPT_IN (3U)

#define FS_INTERRUPT_IN_PACKET_SIZE (8U)
#define HS_INTERRUPT_IN_PACKET_SIZE (8U)

#define FS_INTERRUPT_IN_INTERVAL (8U)
#define HS_INTERRUPT_IN_INTERVAL (7U)

#define FS_BULK_IN_PACKET_SIZE (64U)
#define HS_BULK_IN_PACKET_SIZE (64U)
#define FS_BULK_OUT_PACKET_SIZE (64U)
#define HS_BULK_OUT_PACKET_SIZE (64U)

#define USB_DEVICE_CCID_VERSION (0x0110U)
#define USB_DEVICE_CCID_SMART_CARD_MAX_SLOTS (1U)
#define USB_DEVICE_CCID_SMART_CARD_SLOT_INDEX (0U)
#define USB_DEVICE_CCID_SMART_CARD_VOLTAGE_SUPPORT (USB_DEVICE_CCID_DESCRIPTOR_VOLTAGE_SUPPORT_BM_3V)
#define USB_DEVICE_CCID_SMART_CARD_PROTOCOLS \
  (USB_DEVICE_CCID_DESCRIPTOR_PROTOCOLS_BM_T0)
#define USB_DEVICE_CCID_SMART_CARD_DEFAULT_CLOCK (0x00000DFCU)                              /* KHz */
#define USB_DEVICE_CCID_SMART_CARD_MAXIMUM_CLOCK (USB_DEVICE_CCID_SMART_CARD_DEFAULT_CLOCK) /* KHz */
#define USB_DEVICE_CCID_SMART_CARD_NUM_CLOCK_SUPPORTED (0U)

#define USB_DEVICE_CCID_SMART_CARD_DATA_RATE (0x00002580U)                                  /* bps */
#define USB_DEVICE_CCID_SMART_CARD_MAXIMUM_DATA_RATE (USB_DEVICE_CCID_SMART_CARD_DATA_RATE) /* bps */
#define USB_DEVICE_CCID_SMART_CARD_NUM_DATA_RATE_SUPPORTED (0U)

#define USB_DEVICE_CCID_SMART_CARD_MAX_IFSD (1100U)
#define USB_DEVICE_CCID_SMART_CARD_SYNCH_PROTOCOLS (0x00000000U)
#define USB_DEVICE_CCID_SMART_CARD_MECHANICAL (USB_DEVICE_CCID_DESCRIPTOR_MECHANICAL_BM_NO)

#define USB_DEVICE_CCID_SMART_CARD_FEATURES_INTERNAL                                                             \
    (USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_NO | USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_AUTO_VOLTAGE_SELECTION | \
     USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_AUTO_FREQUENCY_CHANGE |                                              \
     USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_AUTO_BAUD_RATE_CHANGE |                                              \
     USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_AUTO_VOLTAGE_SELECTION |                                             \
USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_SHORT_EXTENDED_APDU_LEVEL_EXCHANGES | \
  0 )

#if 0
USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_TPDU_LEVEL_EXCHANGES | \
     USB_DEVICE_CCID_DESCRIPTOR_FEATURES_BM_SHORT_APDU_LEVEL_EXCHANGES)
#endif



#define USB_DEVICE_CCID_SMART_CARD_FEATURES (USB_DEVICE_CCID_SMART_CARD_FEATURES_INTERNAL)

#define USB_DEVICE_CCID_SMART_CARD_MAX_MESSAGE_LENGTH (USB_DEVICE_CONFIG_CCID_MAX_MESSAGE_LENGTH)
#define USB_DEVICE_CCID_SMART_CARD_CLASS_GET_RESPONSE (0x00U)
#define USB_DEVICE_CCID_SMART_CARD_CLASS_ENVELOPE (0x00U)
#define USB_DEVICE_CCID_SMART_CARD_LCD_LAYOUT (0x0000U)
#define USB_DEVICE_CCID_SMART_CARD_PIN_SUPPORT (USB_DEVICE_CCID_DESCRIPTOR_PIN_SUPPORT_BM_NO)
#define USB_DEVICE_CCID_SMART_CARD_MAX_BUSY_SLOTS (0x01U)

/*******************************************************************************
 * API
 ******************************************************************************/

/* Configure the device according to the USB speed. */
extern usb_status_t USB_DeviceSetSpeed(usb_device_handle handle, uint8_t speed);

/* Get device descriptor request */
usb_status_t USB_DeviceGetDeviceDescriptor(usb_device_handle handle,
                                           usb_device_get_device_descriptor_struct_t *deviceDescriptor);

/* Get device configuration descriptor request */
usb_status_t USB_DeviceGetConfigurationDescriptor(
    usb_device_handle handle, usb_device_get_configuration_descriptor_struct_t *configurationDescriptor);

/* Get device string descriptor request */
usb_status_t USB_DeviceGetStringDescriptor(usb_device_handle handle,
                                           usb_device_get_string_descriptor_struct_t *stringDescriptor);

/* Get hid descriptor request */
usb_status_t USB_DeviceGetHidDescriptor(usb_device_handle handle,
                                        usb_device_get_hid_descriptor_struct_t *hidDescriptor);

/* Get hid report descriptor request */
usb_status_t USB_DeviceGetHidReportDescriptor(usb_device_handle handle,
                                              usb_device_get_hid_report_descriptor_struct_t *hidReportDescriptor);

/* Get hid physical descriptor request */
usb_status_t USB_DeviceGetHidPhysicalDescriptor(usb_device_handle handle,
                                                usb_device_get_hid_physical_descriptor_struct_t *hidPhysicalDescriptor);

#endif /* __USB_DEVICE_DESCRIPTOR_H__ */
