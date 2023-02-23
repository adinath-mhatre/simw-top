/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2021 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


 /***********************************************************************************************************************
 * This file was generated by the MCUXpresso Config Tools. Any manual edits made to this file
 * will be overwritten if the respective MCUXpresso Config Tools is used to update this file.
 **********************************************************************************************************************/

/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
!!GlobalInfo
product: Pins v4.1
processor: MIMXRT1062xxxxx
package_id: MIMXRT1062DVL6A
mcu_data: ksdk2_0
processor_version: 0.0.11
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */

#include "fsl_common.h"
#include "fsl_iomuxc.h"
#include "pin_mux.h"



/* FUNCTION ************************************************************************************************************
 *
 * Function Name : BOARD_InitBootPins
 * Description   : Calls initialization functions.
 *
 * END ****************************************************************************************************************/
void BOARD_InitBootPins(void) {
    I2CPins();
    EnetPins();
}

/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
I2CPins:
- options: {callFromInitBoot: 'true', coreID: core0, enableClock: 'true'}
- pin_list:
  - {pin_num: J11, peripheral: LPI2C1, signal: SCL, pin_signal: GPIO_AD_B1_00, slew_rate: Fast, software_input_on: Enable, open_drain: Enable, drive_strength: R0_7,
    pull_up_down_config: Pull_Up_22K_Ohm}
  - {pin_num: K11, peripheral: LPI2C1, signal: SDA, pin_signal: GPIO_AD_B1_01, slew_rate: Fast, software_input_on: Enable, open_drain: Enable, drive_strength: R0_7,
    pull_keeper_select: Keeper, pull_up_down_config: Pull_Up_22K_Ohm}
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */

/* FUNCTION ************************************************************************************************************
 *
 * Function Name : I2CPins
 * Description   : Configures pin routing and optionally pin electrical features for I2C
 *
 * END ****************************************************************************************************************/
void I2CPins(void) {
  CLOCK_EnableClock(kCLOCK_Iomuxc);           /* iomuxc clock (iomuxc_clk_enable): 0x03u */

  IOMUXC_SetPinMux(
      IOMUXC_GPIO_AD_B1_00_LPI2C1_SCL,        /* GPIO_AD_B1_00 is configured as LPI2C1_SCL */
      1U);                                    /* Software Input On Field: Force input path of pad GPIO_AD_B1_00 */
  IOMUXC_SetPinMux(
      IOMUXC_GPIO_AD_B1_01_LPI2C1_SDA,        /* GPIO_AD_B1_01 is configured as LPI2C1_SDA */
      1U);                                    /* Software Input On Field: Force input path of pad GPIO_AD_B1_01 */
  IOMUXC_SetPinConfig(
      IOMUXC_GPIO_AD_B1_00_LPI2C1_SCL,        /* GPIO_AD_B1_00 PAD functional properties : */
      0xD8B9u);                               /* Slew Rate Field: Fast Slew Rate
                                                 Drive Strength Field: R0/7
                                                 Speed Field: medium(100MHz)
                                                 Open Drain Enable Field: Open Drain Enabled
                                                 Pull / Keep Enable Field: Pull/Keeper Enabled
                                                 Pull / Keep Select Field: Keeper
                                                 Pull Up / Down Config. Field: 22K Ohm Pull Up
                                                 Hyst. Enable Field: Hysteresis Disabled */
  IOMUXC_SetPinConfig(
      IOMUXC_GPIO_AD_B1_01_LPI2C1_SDA,        /* GPIO_AD_B1_01 PAD functional properties : */
      0xD8B9u);                               /* Slew Rate Field: Fast Slew Rate
                                                 Drive Strength Field: R0/7
                                                 Speed Field: medium(100MHz)
                                                 Open Drain Enable Field: Open Drain Enabled
                                                 Pull / Keep Enable Field: Pull/Keeper Enabled
                                                 Pull / Keep Select Field: Keeper
                                                 Pull Up / Down Config. Field: 22K Ohm Pull Up
                                                 Hyst. Enable Field: Hysteresis Disabled */
}


void EnetPins(void)
{
      CLOCK_EnableClock(kCLOCK_Iomuxc);           /* iomuxc clock (iomuxc_clk_enable): 0x03u */

      IOMUXC_SetPinMux(
          IOMUXC_GPIO_AD_B0_09_GPIO1_IO09,        /* GPIO_AD_B0_09 is configured as GPIO1_IO09 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_AD_B0_10_GPIO1_IO10,        /* GPIO_AD_B0_10 is configured as GPIO1_IO10 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_AD_B0_12_LPUART1_TX,        /* GPIO_AD_B0_12 is configured as LPUART1_TX */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_AD_B0_13_LPUART1_RX,        /* GPIO_AD_B0_13 is configured as LPUART1_RX */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_04_ENET_RX_DATA00,       /* GPIO_B1_04 is configured as ENET_RX_DATA00 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_05_ENET_RX_DATA01,       /* GPIO_B1_05 is configured as ENET_RX_DATA01 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_06_ENET_RX_EN,           /* GPIO_B1_06 is configured as ENET_RX_EN */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_07_ENET_TX_DATA00,       /* GPIO_B1_07 is configured as ENET_TX_DATA00 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_08_ENET_TX_DATA01,       /* GPIO_B1_08 is configured as ENET_TX_DATA01 */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_09_ENET_TX_EN,           /* GPIO_B1_09 is configured as ENET_TX_EN */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_10_ENET_REF_CLK,         /* GPIO_B1_10 is configured as ENET_REF_CLK */
          1U);                                    /* Software Input On Field: Force input path of pad GPIO_B1_10 */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_B1_11_ENET_RX_ER,           /* GPIO_B1_11 is configured as ENET_RX_ER */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_EMC_40_ENET_MDC,            /* GPIO_EMC_40 is configured as ENET_MDC */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinMux(
          IOMUXC_GPIO_EMC_41_ENET_MDIO,           /* GPIO_EMC_41 is configured as ENET_MDIO */
          0U);                                    /* Software Input On Field: Input Path is determined by functionality */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_AD_B0_09_GPIO1_IO09,        /* GPIO_AD_B0_09 PAD functional properties : */
          0xB0A9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: medium(100MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_AD_B0_10_GPIO1_IO10,        /* GPIO_AD_B0_10 PAD functional properties : */
          0xB0A9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: medium(100MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_AD_B0_12_LPUART1_TX,        /* GPIO_AD_B0_12 PAD functional properties : */
          0x10B0u);                               /* Slew Rate Field: Slow Slew Rate
                                                     Drive Strength Field: R0/6
                                                     Speed Field: medium(100MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Keeper
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Down
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_AD_B0_13_LPUART1_RX,        /* GPIO_AD_B0_13 PAD functional properties : */
          0x10B0u);                               /* Slew Rate Field: Slow Slew Rate
                                                     Drive Strength Field: R0/6
                                                     Speed Field: medium(100MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Keeper
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Down
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_04_ENET_RX_DATA00,       /* GPIO_B1_04 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_05_ENET_RX_DATA01,       /* GPIO_B1_05 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_06_ENET_RX_EN,           /* GPIO_B1_06 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_07_ENET_TX_DATA00,       /* GPIO_B1_07 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_08_ENET_TX_DATA01,       /* GPIO_B1_08 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_09_ENET_TX_EN,           /* GPIO_B1_09 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_10_ENET_REF_CLK,         /* GPIO_B1_10 PAD functional properties : */
          0x31u);                                 /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/6
                                                     Speed Field: low(50MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Disabled
                                                     Pull / Keep Select Field: Keeper
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Down
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_B1_11_ENET_RX_ER,           /* GPIO_B1_11 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_EMC_40_ENET_MDC,            /* GPIO_EMC_40 PAD functional properties : */
          0xB0E9u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: max(200MHz)
                                                     Open Drain Enable Field: Open Drain Disabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
      IOMUXC_SetPinConfig(
          IOMUXC_GPIO_EMC_41_ENET_MDIO,           /* GPIO_EMC_41 PAD functional properties : */
          0xB829u);                               /* Slew Rate Field: Fast Slew Rate
                                                     Drive Strength Field: R0/5
                                                     Speed Field: low(50MHz)
                                                     Open Drain Enable Field: Open Drain Enabled
                                                     Pull / Keep Enable Field: Pull/Keeper Enabled
                                                     Pull / Keep Select Field: Pull
                                                     Pull Up / Down Config. Field: 100K Ohm Pull Up
                                                     Hyst. Enable Field: Hysteresis Disabled */
}

/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
