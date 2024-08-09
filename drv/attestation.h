#ifndef __ATTESTATION_H
#define __ATTESTATION_H
#include <stdint.h>
#include "partition.h"
//=======================defines============================
#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define HASH_LEN (32u)
typedef struct
{
    uint8_t               hash[HASH_LEN];        // the hash result
    uint32_t              attestation_status;    // the status of attestation operation, 0 is success
} attestation_result_t;
/**
 * @brief get the hashed image value on active partition
 *
*/
attestation_result_t edhoc_initial_attest_get_hashed_image (db_partitions_table_t *partitions);
#endif //__ATTESTATION_H