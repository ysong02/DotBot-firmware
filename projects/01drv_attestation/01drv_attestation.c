/**
 * @file
 * @author Yuxuan SONG <yuxuan.song@inria.fr>
 * @brief This application can be flashed on partition 0 (at 0x2000)
 *
 * sample attestation, generate the attestation token (can be seen in debug mode)
 * @copyright Inria, 2024
 *
 */
#include <stdio.h>
#include <stdint.h>
#include "partition.h"
#include "attestation.h"
#include "sha256.h"

//=======================defines==============================================

//================================ variables =================================
const uint8_t challenge[EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8] = {0xa2, 0x9f, 0x62, 0xa4, 0xc6, 0xcd, 0xaa, 0xe5}; //should receive from the verifier
uint8_t token_buf[MAX_TOKEN];
uint8_t token_size;
//================================ main ======================================

int main (void){
     
    attestation_status_t status = edhoc_initial_attest_signed_token(challenge, token_buf, &token_size);
    if (status != 0){
        printf("Attestation token generation: FAIL");
        return ATTESTATION_ERROR;
    }
    printf("Attestation token generation: SUCCESS");
    return 0;

}
