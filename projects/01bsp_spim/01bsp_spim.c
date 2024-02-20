/**
 * @file
 * @ingroup samples_bsp
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @brief This is a short example of how to use the SPIM api.
 *
 * @copyright Inria, 2024-present
 *
 */
#include <nrf.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "gpio.h"
#include "spim.h"

//============================ defines =========================================

#define SX127X_REG_OPMODE       (0x01)
#define SX1276_REG_VERSION      (0x42)
#define SX1276_VERSION_EXPECTED (0x12)

#define SPIM_FREQUENCY DB_SPIM_FREQ_4M

//=========================== variables ========================================

// static const uint8_t _data_to_send[] = {0x41, 0x42, 0x43, 0x44, 0x45};

static const gpio_t _sck_pin  = { .port = 1, .pin = 15 };
static const gpio_t _miso_pin = { .port = 1, .pin = 14 };
static const gpio_t _mosi_pin = { .port = 1, .pin = 13 };
static const gpio_t _cs_pin   = { .port = 1, .pin = 12 };

const db_spim_conf_t _spim_conf = {
    .mosi = &_mosi_pin,
    .sck  = &_sck_pin,
    .miso = &_miso_pin,
};

static void _read_reg(uint8_t reg, uint8_t *value) {
    db_spim_begin(&_cs_pin, DB_SPIM_MODE_0, SPIM_FREQUENCY);
    db_spim_transfer(&reg, NULL, 1);
    db_spim_transfer(NULL, value, 1);
    db_spim_end(&_cs_pin);
}

static void _write_reg(uint8_t reg, uint8_t value) {
    db_spim_begin(&_cs_pin, DB_SPIM_MODE_0, SPIM_FREQUENCY);
    db_spim_transfer(&reg, NULL, 1);
    db_spim_transfer(&value, NULL, 1);
    db_spim_end(&_cs_pin);
}

//=========================== main =============================================

int main(void) {
    db_spim_init(&_spim_conf);

    db_gpio_init(&_cs_pin, DB_GPIO_OUT);
    db_gpio_set(&_cs_pin);

    uint8_t version_addr = SX1276_REG_VERSION;
    uint8_t version      = 0;
    _read_reg(version_addr, &version);
    if (version != SX1276_VERSION_EXPECTED) {
        printf("[ERROR] Invalid SX1276 version: %d (expected: %d)\n", version, SX1276_VERSION_EXPECTED);
        assert(false);
    }

    uint8_t op_mode      = 0;
    uint8_t op_mode_addr = SX127X_REG_OPMODE;  // Sleep mode
    _write_reg(op_mode_addr, op_mode);

    puts("Success!");
    while (1) {
        __WFE();
    }
}
