#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "partition.h"
#include "attestation.h"
#include "sha256.h"
//================================ defines =================================
#define CHUNK_LEN (1024U)
//================================ variables =================================
static attestation_result_t _attestation_result = { 0 };
//================================ functions =================================
attestation_result_t edhoc_initial_attest_get_hashed_image (db_partitions_table_t *partition_table){
    
    //success by default, change it later (attestation_status = 0)
    db_read_partitions_table(partition_table);

    //find the start of image, the size of the image
    uint32_t image_address = partition_table->partitions[partition_table->active_image].address;
    uint32_t image_size = partition_table->partitions[partition_table->active_image].size;

    //initialize crypto 
    crypto_sha256_init();

    //loop over chunk of current partition flash memory
    for (uint32_t current_address = image_address; current_address < (image_address + image_size); current_address += CHUNK_LEN) {
        uint8_t tmp[CHUNK_LEN] = { 0 };
        memcpy(tmp, (uint32_t *)current_address, CHUNK_LEN);
        crypto_sha256_update(tmp, CHUNK_LEN);
    }

    // finalize sha256
    crypto_sha256(_attestation_result.hash);   
    return _attestation_result;
}