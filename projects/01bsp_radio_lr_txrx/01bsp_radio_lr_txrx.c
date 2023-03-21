/**
 * @file 01bsp_radio_lr_txrx.c
 * @author Trifun savic <trifun.savic@inria.fr>
 * @brief This is a short example of how to interface with the Long Range BLE radio.
 *
 *
 *
 * @copyright Inria, 2022
 *
 */
#include <nrf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include BSP packages
#include "board.h"
#include "gpio.h"
#include "radio.h"

//=========================== defines =========================================

#define NUMBER_OF_BYTES_IN_PACKET 32

//=========================== variables =========================================

static uint8_t packet_tx[NUMBER_OF_BYTES_IN_PACKET];

static const gpio_t _dbg_pin = { .port = 0, .pin = 31 };

//=========================== prototypes =========================================

void radio_callback(uint8_t *packet, uint8_t length);

//=========================== main =========================================

/**
 *  @brief The program starts executing here.
 */
int main(void) {

    // Turn ON the DotBot board regulator
    db_board_init();

    //=========================== Initialize GPIO =========================================

    db_gpio_init(&_dbg_pin, DB_GPIO_OUT);

    memset(packet_tx, 0, NUMBER_OF_BYTES_IN_PACKET);
    packet_tx[0] = 0x01;

    //=========================== Configure Radio =========================================

    db_radio_init(&radio_callback, DB_RADIO_BLE_LR125Kbit);
    db_radio_set_frequency(8);  // Set the RX frquency to 2408 MHz.

    db_radio_tx(packet_tx, NUMBER_OF_BYTES_IN_PACKET);
    db_radio_rx_enable();  // Start receiving packets.

    while (1) {

        __WFE();
        __SEV();
        __WFE();
    }

    // one last instruction, doesn't do anything, it's just to have a place to put a breakpoint.
    __NOP();
}

//=========================== functions =========================================

/**
 *  @brief Callback function to process received packets
 *
 * This function gets called each time a packet is received.
 *
 * @param[in] packet pointer to the array of data to send over the radio (max size = 32)
 * @param[in] length Number of bytes to send (max size = 32)
 *
 */
void radio_callback(uint8_t *packet, uint8_t length) {
    (void)length;

    // Check the arriving packet for any pressed button.
    if (packet[0] == 0x01 || packet[1] == 0x01 || packet[2] == 0x01 || packet[3] == 0x01) {
        db_gpio_set(&_dbg_pin);
    } else {
        db_gpio_clear(&_dbg_pin);
    }
}
