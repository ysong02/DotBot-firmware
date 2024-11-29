#ifndef __ATTESTATION_H
#define __ATTESTATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "partition.h"
#include "C:/Users/yusong/Downloads/test-edhoc-handshake/lakers/target/include/lakers.h"

//=======================defines============================

#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8 (8u)
//#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
//#define EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define PROVIDED_EVIDENCE_TYPE (258u)
#define HASH_LEN (32u)
#define MAX_UEID (33u)
#define MAX_TOKEN              (500U)

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

uint8_t cborencoder_put_array(uint8_t *buffer, uint8_t elements);
uint8_t cborencoder_put_unsigned(uint8_t *buffer, unsigned long value);
/**
 * @brief encode the array an bytes in CBOR, and return a int indicating the length of cbor output
 */

uint8_t decode_ead_2(uint8_t *buffer, uint32_t *decoded_integer, uint8_t *decoded_bytes, uint8_t *decoded_length);
/**
 * @brief decode the ead_2 and get the value of selected evidence type and nonce
 */

attestation_status_t edhoc_initial_attest_signed_token(const uint8_t challenge[EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8], uint8_t *token_buf, uint8_t *token_size);
/**
 * @brief generate a COSE_Sign1 token 
 */
void prepare_ead_1 (EADItemC *ead, uint8_t label, bool is_critical);
void prepare_ead_3 (EADItemC *ead_3, uint8_t label, bool is_critical, uint8_t *decoded_nonce, uint8_t *token_size);

#endif //__ATTESTATION_H