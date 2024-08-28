#ifndef __ATTESTATION_H
#define __ATTESTATION_H

#include <stdint.h>
#include <stddef.h>
#include "partition.h"

//=======================defines============================

#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8 (8u)
//#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
//#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define HASH_LEN (32u)
#define MAX_UEID (33u)
#define MAX_TOKEN               (500U)

///< attestation status enumeration
typedef enum {
    ATTESTATION_SUCCESS = 0, 
    ATTESTATION_ERROR = -1, 
    ATTESTATION_ERROR_INVALID_IMAGE = -2, 
    ATTSETATION_ERROR_CBOR_TOO_MANY_ELEMENTS = -3, 
    ATTESTATION_ERROR_CBOR_ENCODING = -4,
    ATTESTATION_ERROR_EVIDENCE = -5,
    ATTESTATION_ERROR_MEASUREMENTS = -6,
    ATTESTATION_ERROR_TOKEN = -7,
    ATTESTATION_ERROR_CBOR_PUT_NEGATIVE = -8,
    ATTESTATION_ERROR_SIGNATURE = -9
    } attestation_status_t;
           
//================================ functions =================================

attestation_status_t edhoc_initial_attest_signed_token(const uint8_t challenge[EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8], uint8_t *token_buf, uint8_t *token_size);
/**
 * @brief generate a COSE_Sign1 token 
 */

#endif //__ATTESTATION_H