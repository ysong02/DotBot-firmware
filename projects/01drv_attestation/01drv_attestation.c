#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include "partition.h"
#include "attestation.h"
#include "sha256.h"

//=======================defines==============================================

//#define DB_PARTITIONS_TABLE_ADDRESS (0x00001000UL + DB_FLASH_OFFSET)

//================================ variables =================================
const uint8_t challenge[EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8] = {0xa2, 0x9f, 0x62, 0xac, 0xc6, 0xcd, 0xaa, 0xe5};
uint8_t token_buf[MAX_TOKEN];
uint8_t token_size;
//================================ main ======================================

int main (void){
    // attestation_result_t result = edhoc_initial_attest_get_hashed_image (&_table);
    // printf("Attestation Status: %d\n", result.attestation_status);
    // printf("Attestation Hash result:");
    // for (uint8_t i = 0; i < HASH_LEN; i++){
    //     printf("%02x", result.hash[i]);
    // }
    
    attestation_status_t status = 0;
    status = edhoc_initial_attest_signed_token(challenge, token_buf, &token_size);
    if (status != 0){
        printf("final attestation result: failed");
        return ATTESTATION_ERROR;
    }
    printf("final attestation result: success");
    return 0;

}
