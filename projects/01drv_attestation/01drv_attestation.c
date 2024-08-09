#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include "partition.h"
#include "attestation.h"

#include "sha256.h"

#define DB_PARTITIONS_TABLE_ADDRESS (0x00001000UL + DB_FLASH_OFFSET)
//================================ variables =================================
static db_partitions_table_t _table = { 0 };

//================================ main =======================================

int main (void){
    attestation_result_t result = edhoc_initial_attest_get_hashed_image (&_table);
    printf("Attestation Status: %d\n", result.attestation_status);
    printf("Attestation Hash result:");
    for (uint8_t i = 0; i < HASH_LEN; i++){
        printf("%02x", result.hash[i]);
    }
    
    return 0;

}
