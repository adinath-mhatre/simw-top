/* Copyright 2018-2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "sm_timer.h"
#include "ax_reset.h"
#include "se05x_apis.h"

#define IMX_GPIO_NR(port, index) ((((port)-1) * 32) + ((index)&31))
#define IMX_RESET_PORT 2
#define IMX_RESET_PIN 21

#define EN_PIN IMX_GPIO_NR(IMX_RESET_PORT, IMX_RESET_PIN)

#define LOG_ERROR(X)

// #define LOG_ERROR(X) perror(X)

void axReset_HostConfigure()
{
    int fd;
    char buf[50];
    /* Open export file to export GPIO */
    fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open GPIO export file ");
        return;
    }
    /* Export GPIO pin to toggle */
    snprintf(buf, sizeof(buf), "%d", EN_PIN);
    if (write(fd, buf, strlen(buf)) < 1) {
        LOG_ERROR("Failed to export Enable pin ");
        goto exit;
    }
    close(fd);

    /* Open direction file to configure GPIO direction */
    snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/direction", EN_PIN);
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        sm_usleep(1000 * 1000);
        fd = open(buf, O_WRONLY);
        if (fd < 0) {
            axReset_HostUnconfigure();
            LOG_ERROR("Failed to open GPIO direction file ");
            return;
        }
    }
    /* Configure direction of exported GPIO */
    if (write(fd, "out", 3) < 1) {
        LOG_ERROR("Failed to Configure Enable pin ");
        axReset_HostUnconfigure();
        goto exit;
    }

exit:
    close(fd);
    return;
}

void axReset_HostUnconfigure()
{
    int fd;
    char buf[50];
    fd = open("/sys/class/gpio/unexport", O_WRONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open unexport file ");
        return;
    }

    snprintf(buf, sizeof(buf), "%d", EN_PIN);
    if (write(fd, buf, strlen(buf)) < 1) {
        LOG_ERROR("Failed to unexport GPIO ");
    }

    close(fd);
    return;
}

/*
 * Where applicable, PowerCycle the SE
 *
 * Pre-Requisite: @ref axReset_Configure has been called
 */
void axReset_ResetPluseDUT()
{
    axReset_PowerDown();
    sm_usleep(2000);
    axReset_PowerUp();
    return;
}

/*
 * Where applicable, put SE in low power/standby mode
 *
 * Pre-Requisite: @ref axReset_Configure has been called
 */
void axReset_PowerDown()
{
    int fd;
    char buf[50];
    char logic[10];
    snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", EN_PIN);
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open GPIO value file ");
        axReset_HostUnconfigure();
        return;
    }

    snprintf(logic, sizeof(logic), "%d", !SE_RESET_LOGIC);
    if (write(fd, logic, 1) < 1) {
        LOG_ERROR("Failed to toggle GPIO high ");
        axReset_HostUnconfigure();
    }

    close(fd);
}

/*
 * Where applicable, put SE in powered/active mode
 *
 * Pre-Requisite: @ref axReset_Configure has been called
 */
void axReset_PowerUp()
{
    int fd;
    char buf[50];
    char logic[10];
    snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%d/value", EN_PIN);
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open GPIO value file ");
        axReset_HostUnconfigure();
        return;
    }

    snprintf(logic, sizeof(logic), "%d", SE_RESET_LOGIC);
    if (write(fd, logic, 1) < 1) {
        LOG_ERROR("Failed to toggle GPIO high ");
        axReset_HostUnconfigure();
    }

    close(fd);
}

#if SSS_HAVE_APPLET_SE05X_IOT || SSS_HAVE_APPLET_LOOPBACK

void se05x_ic_reset()
{
    axReset_ResetPluseDUT();
    smComT1oI2C_ComReset();
    sm_usleep(3000);
    return;
}

#endif
