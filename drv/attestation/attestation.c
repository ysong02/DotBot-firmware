
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "partition.h"
#include "attestation.h"
#include "sha256.h"
#include "ed25519.h"



//================================ defines =================================

#define ED25519_SIGNATURE_LEN   (64U)
#define ED25519_PRIVATE_KEY_LEN (32U)
#define ED25519_PUBLIC_KEY_LEN  (32U)
#define MAX_FS_NAME             (64U)
#define MAX_ENTITY_NAME         (32U)
#define MAX_SOFTWARE_NAME       (32U)
#define MAX_TAG_ID              (32U)

#define IANA_CBOR_COSWID_FILE_FS_NAME_KEY 24
#define IANA_CBOR_COSWID_FILE_SIZE_KEY 20
#define IANA_CBOR_COSWID_FILE_HASH_IMAGE_KEY 7
#define IANA_CBOR_COSWID_FILE_KEY 17

#define IANA_CBOR_COSWID_ENTITY_ENTITY_NAME_KEY  31
#define IANA_CBOR_COSWID_ENTITY_ROLE  33

#define IANA_CBOR_COSWID_TAG_ID_KEY  0
#define IANA_CBOR_COSWID_TAG_VERSION_KEY 12
#define IANA_CBOR_COSWID_SOFTWARE_NAME_KEY  1
#define IANA_CBOR_COSWID_ENTITY_KEY  2
#define IANA_CBOR_COSWID_EVIDENCE_KEY  3

#define IANA_CBOR_EAT_UEID_KEY  256
#define IANA_CBOR_EAT_NONCE_KEY  10
#define IANA_CBOR_EAT_MEASUREMENTS_KEY  273 

#define IANA_COAP_CONTENT_FORMATS_SWID  258

#define IANA_COSE_HEADER_PARAMETERS_ALG  1

//define CoSWID file 
typedef struct 
{
    char fs_name[MAX_FS_NAME]; //(index 24)
    uint32_t size; //(index 20)
    uint8_t hash_alg;  
    uint8_t hash_image[HASH_LEN];  //(index 7)
}file_t;

//define CoSWID evidence 
typedef struct 
{
    file_t file; //(index 17), currently only one file inside
}evidence_t;

//define CoSWID entity
typedef struct 
{
    char entity_name[MAX_ENTITY_NAME];  //(index 31)
    uint8_t role; //(index 33)
}entity_t;
 
//define CoSWID 
typedef struct 
{
    char tag_id[MAX_TAG_ID]; //(index 0)
    uint8_t tag_version;  //(index 12)
    char software_name[MAX_SOFTWARE_NAME];  //(index 1)
    entity_t entity;  //(index 2)
    evidence_t evidence; //(index 3)
}coswid_t;

//define measurements claim
typedef struct 
{
    int content_format_id;  
    coswid_t coswid;
}measurements_claim_t; //currently only one coswid inside

//define token structure
typedef struct 
{
    char ueid[MAX_UEID];  //(index 256)
    uint8_t nonce[EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8];  //(index 10)
    measurements_claim_t measurements; //(index 273)
}token_t;
 

//================================ variables =================================

static attestation_status_t status = 0;
uint8_t hash[HASH_LEN] = {0};
static evidence_t evidence = {0};
static measurements_claim_t claim = {0};
static token_t token = {0};
static uint8_t signature[ED25519_SIGNATURE_LEN] = {0};
uint8_t ret;
uint8_t token_buf[MAX_TOKEN];
db_partitions_table_t _table = {0};

const uint8_t public_key[32] = {
    0xb2, 0x4f, 0x6d, 0x4e, 0x5f, 0x81, 0x47, 0xaf, 0x1d, 0x1c, 0xd8, 0xc2, 0x6e, 0x1a, 0x51, 0x0b, 0x7a, 0x0f, 0x7f, 0x0a, 0x7b, 0xcc, 0x60, 0x68, 0x89, 0x55, 0xd3, 0x27, 0xb9, 0x9c, 0x64, 0x75
};

const uint8_t private_key[32] = {
    0xf3, 0x8f, 0x0d, 0xd6, 0x13, 0x62, 0x06, 0x3c, 0xd7, 0xa1, 0xdf, 0x84, 0x6b, 0x8a, 0x56, 0x2e, 0x9c, 0x60, 0x55, 0x80, 0xe9, 0x95, 0xed, 0xe9, 0x5f, 0x64, 0x47, 0xc5, 0x04, 0x44, 0x96, 0x87
};

//================================ private =================================

/**
 * @brief CBOR encoding funcitons
 */

uint8_t cborencoder_put_map(uint8_t *buffer, uint8_t elements) {
    uint8_t ret = 0;

    if (elements > 15) {
        return ATTSETATION_ERROR_CBOR_TOO_MANY_ELEMENTS;
    }

    buffer[ret++] = (0xa0 | elements);
    return ret;
}

uint8_t cborencoder_put_null(uint8_t *buffer) {
    uint8_t ret = 0;

    buffer[ret++] = 0xf6;
    return ret;
}

//allow 32-bit integer
uint8_t cborencoder_put_unsigned(uint8_t *buffer, unsigned long value) {
    uint8_t ret = 0;

    if (value <= 0x17){
        buffer[ret++] = value;
    } else if (value <= 0xff){
        buffer[ret++] = 0x18;
        buffer[ret++] = value;
    } else if (value <= 0xffff)
    {
        buffer[ret++] = 0x19;
        buffer[ret++] = (value >> 8)& 0xff;
        buffer[ret++] = value & 0xff;
    } else if (value <= 0xffffffff){
        buffer[ret++] = 0x1a;
        buffer[ret++] = (value >> 24)& 0xff;
        buffer[ret++] = (value >> 16)& 0xff;
        buffer[ret++] = (value >> 8) & 0xff;
        buffer[ret++] = value & 0xff;
    }

    return ret;
}

//only for -1 to -15
uint8_t cborencoder_put_negative(uint8_t *buffer, int8_t value) {
    uint8_t ret = 0;

    if (value >= 0){
        return ATTESTATION_ERROR_CBOR_PUT_NEGATIVE;
    } else {
        buffer[ret++] = (0x20 | -1 - value);   
    }
    return ret;
}

uint8_t cborencoder_put_bytes(uint8_t *buffer, const uint8_t *bytes, uint8_t bytes_len) {
    uint8_t ret = 0;

    if (bytes_len > 23) {
        buffer[ret++] = 0x58;
        buffer[ret++] = bytes_len;
    } else {
        buffer[ret++] = (0x40 | bytes_len);
    }

    if (bytes_len != 0 && bytes != NULL) {
        memcpy(&buffer[ret], bytes, bytes_len);
        ret += bytes_len;
    }

    return ret;
}

uint8_t cborencoder_put_array(uint8_t *buffer, uint8_t elements) {
    uint8_t ret = 0;

    if (elements > 15) {
        return 0;
    }

    buffer[ret++] = (0x80 | elements);
    return ret;
}

uint8_t cborencoder_put_text(uint8_t *buffer, const char *text, uint8_t text_len) {
    uint8_t ret = 0;

    if (text_len > 23) {
        buffer[ret++] = 0x78;
        buffer[ret++] = text_len;
    } else {
        buffer[ret++] = (0x60 | text_len);
    }

    if (text_len != 0 && text != NULL) {
        memcpy(&buffer[ret], text, text_len);
        ret += text_len;
    }

    return ret;
}

/**
 * @brief CBOR decoding functions 
 */
 uint8_t cbor_decode_unsigned(uint8_t *buffer, uint32_t *value) {
    uint8_t ret = 0;
    uint8_t lead_byte = buffer[0];

    if (lead_byte <= 0x17) {
        *value = lead_byte;
        ret = 1;  
    } else if (lead_byte == 0x18) {
        *value = buffer[1];
        ret = 2;  
    } else if (lead_byte == 0x19) {
        *value = (buffer[1] << 8) | buffer[2];
        ret = 3;  
    } else if (lead_byte == 0x1a) {
        *value = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
        ret = 5;  
    } else {
        ret = 0;  
    }

    return ret;
}

uint8_t cbor_decode_bytestring(uint8_t *buffer, uint8_t *output, uint8_t *length) {
    uint8_t ret = 0;
    uint8_t lead_byte = buffer[0];

    if (lead_byte >= 0x40 && lead_byte <= 0x57) {
        *length = lead_byte - 0x40;
        memcpy(output, &buffer[1], *length);
        ret = 1 + *length;
    } else if (lead_byte == 0x58) {
        *length = buffer[1];
        memcpy(output, &buffer[2], *length);
        ret = 2 + *length;
    } else {
        ret = 0;  
    }

    return ret;
}

/**
 * @brief decode the ead_2 (attestation request) and get the value of evidence type and nonce
 */
uint8_t decode_ead_2(uint8_t *buffer, uint32_t *decoded_integer, uint8_t *decoded_bytes, uint8_t *decoded_length) {
    uint8_t index = 0;
    uint8_t first_byte = buffer[index++];
    if (first_byte != 0x82 ){
        return -1;
        }
    printf("first index is: \n");
    printf("%02x\n", index);

    index += cbor_decode_unsigned(buffer+index, decoded_integer);
    printf("%02x\n", index);
    if (index == 0) {
        return -1;  
    }
  
    index += cbor_decode_bytestring(buffer+index, decoded_bytes, decoded_length);
    printf("%02x\n", index); 
    if (index == 0) {
        return -2; 
    }

    return 0;
}

/**
 * @brief get the encoding format of evidence
 */
static attestation_status_t edhoc_initial_attest_encode_evidence(uint8_t *buffer, evidence_t *evidence, uint8_t *token_size){
    *token_size += cborencoder_put_map(&buffer[*token_size], 1); //changeable, one evidence element
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_FILE_KEY); 
    *token_size += cborencoder_put_array(&buffer[*token_size], 1); // changeable, one file in the array
    *token_size += cborencoder_put_map(&buffer[*token_size], 3); //fixed, three index for the file map
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_FILE_FS_NAME_KEY); 
    *token_size += cborencoder_put_text(&buffer[*token_size], evidence->file.fs_name, strlen(evidence->file.fs_name));
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_FILE_SIZE_KEY);
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], evidence->file.size); // need to extend the put_unsigned function 
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_FILE_HASH_IMAGE_KEY);
    *token_size += cborencoder_put_array(&buffer[*token_size], 2); //fixed, two attributes in hashed value array
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], 1); //fixed, indicate sha256
    *token_size += cborencoder_put_bytes(&buffer[*token_size], evidence->file.hash_image, HASH_LEN);

    if (*token_size != 0){
        return ATTESTATION_SUCCESS;
    }
    else{
        return ATTESTATION_ERROR_CBOR_ENCODING;
    }

}

/**
 * @brief get the encoding format 
 */
static attestation_status_t edhoc_initial_attest_encode_measurements(uint8_t *buffer, measurements_claim_t *measurements, uint8_t *token_size){
    *token_size += cborencoder_put_map(&buffer[*token_size], 5);  //fixed, 5 elements in measurements claim
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_TAG_ID_KEY);
    *token_size += cborencoder_put_text(&buffer[*token_size], measurements->coswid.tag_id, strlen(measurements->coswid.tag_id));
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_SOFTWARE_NAME_KEY);
    *token_size += cborencoder_put_text(&buffer[*token_size], measurements->coswid.software_name, strlen(measurements->coswid.software_name));
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_ENTITY_KEY);
    *token_size += cborencoder_put_map(&buffer[*token_size], 2); //fixed, 2 elements in entity
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_ENTITY_ENTITY_NAME_KEY);
    *token_size += cborencoder_put_text(&buffer[*token_size], measurements->coswid.entity.entity_name, strlen(measurements->coswid.entity.entity_name));
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_ENTITY_ROLE);
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], 1); //fixed, indicate tag creator 
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_TAG_VERSION_KEY);
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], measurements->coswid.tag_version); //changeable when the attestation service is recalled, fix to 0 for onboarding check
    
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_COSWID_EVIDENCE_KEY); 
     
    if (*token_size != 0){
        return ATTESTATION_SUCCESS;
    }
    else{
        return ATTESTATION_ERROR_CBOR_ENCODING;
    }     

}

/**
 * @brief get the encoding format 
 */
static attestation_status_t edhoc_initial_attest_encode_token(uint8_t *buffer, token_t *token, uint8_t *token_size){
//transfer the input to CBOR

    *token_size += cborencoder_put_map(&buffer[*token_size], 3);  //fixed
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_EAT_NONCE_KEY);
    *token_size += cborencoder_put_bytes(&buffer[*token_size], token->nonce, EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8);
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_EAT_UEID_KEY);
    *token_size += cborencoder_put_text(&buffer[*token_size], token->ueid, strlen(token->ueid));
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_CBOR_EAT_MEASUREMENTS_KEY);
    *token_size += cborencoder_put_array(&buffer[*token_size], 1); //changeable
    *token_size += cborencoder_put_array(&buffer[*token_size], 2); //fixed, content format id and evidence in an array
    *token_size += cborencoder_put_unsigned(&buffer[*token_size], IANA_COAP_CONTENT_FORMATS_SWID);

    if (*token_size != 0){
        return ATTESTATION_SUCCESS;
    }
    else{
        return ATTESTATION_ERROR_CBOR_ENCODING;
    }    

}

static attestation_status_t edhoc_initial_attest_encode_cose_headers(uint8_t *token_buf, uint8_t *token_size, uint8_t *protected_header_start, uint8_t *protected_header_end){

    token_buf[0] = 0xd2;  //fixed, COSE_Sign1 tag
    token_buf[1] = 0x84;  //fixed, 4 elements in the array
    token_buf[2] = 0x43;  //changeable, 3 bytes for protected header
    *token_size += 3;
    *protected_header_start = *token_size;
    *token_size += cborencoder_put_map(&token_buf[*token_size], 1);  //fixed, one element in protected header
    *token_size += cborencoder_put_unsigned(&token_buf[*token_size], IANA_COSE_HEADER_PARAMETERS_ALG);
    *token_size += cborencoder_put_negative(&token_buf[*token_size], -8);  //changeable, now we use EdDSA which is -8
    *protected_header_end = *token_size;
    *token_size += cborencoder_put_map(&token_buf[*token_size], 0); //changeable, currently nothing in unprotected header 
    if (*token_size != 0){
        return ATTESTATION_SUCCESS;
    }
    else{
        return ATTESTATION_ERROR_CBOR_ENCODING;
    }
}

/**
 * @brief get the hashed image value on active partition
 */
static attestation_status_t edhoc_initial_attest_get_hashed_image (db_partitions_table_t* partition_table, uint8_t hash[HASH_LEN], uint32_t *image_size){
    
    db_read_partitions_table(partition_table);

    //find the start of image, the size of the image
    uint32_t image_address = partition_table->partitions[partition_table->active_image].address;
    *image_size = partition_table->partitions[partition_table->active_image].size;

    // initialize crypto 
    crypto_sha256_init();
    crypto_sha256_update((uint8_t *)image_address, *image_size);

     //finalize sha256
    crypto_sha256(hash);  
    if (hash == NULL){
        return ATTESTATION_ERROR_EVIDENCE;
    }
     
    printf("Attestation Hash result:\n");
    for (uint8_t i = 0; i < HASH_LEN; i++){
        printf("%02x", hash[i]);
    }
    printf("\n");
    return 0;
}

/**
 * @brief fill measurements Claim: using swid+cbor
 */
static attestation_status_t edhoc_initial_attest_evidence_cbor (evidence_t *evidence, uint8_t *token_buf, uint8_t *token_size, uint8_t hash[HASH_LEN], uint32_t *image_size){

    //strcpy(evidence->file.fs_name, "01drv_attestation-nrf52840dk.bin");
    strcpy(evidence->file.fs_name, "03app_dotbot-nrf5340dk-app.bin");
    evidence->file.hash_alg = 1;  //fixed, sha256
    memcpy(evidence->file.hash_image, hash, HASH_LEN);
    evidence->file.size = *image_size;  //!!!!!!!!!!!!!!TBC how to get the size of file in DotBot!!!!!!!!!!!!!!!
    //evidence->file.size = NULL;
    if (evidence == NULL){
        return ATTESTATION_ERROR_EVIDENCE;
    }
    else{
        return edhoc_initial_attest_encode_evidence(token_buf, evidence, token_size);
    }
}

/**
 * @brief fill measurements Claim: using swid+cbor
 */
static attestation_status_t edhoc_initial_attest_measurements_cbor (measurements_claim_t *claim, uint8_t *token_buf, uint8_t *token_size){
    claim->content_format_id = IANA_COAP_CONTENT_FORMATS_SWID;
    //strcpy(claim->coswid.tag_id, "aaa");
    strcpy(claim->coswid.tag_id, "");
    //claim->coswid.tag_version = 0;
    //strcpy(claim->coswid.software_name, "DotBot firmware image 1");
    strcpy(claim->coswid.software_name, "DotBot");
    //strcpy(claim->coswid.entity.entity_name, "Attester");
    strcpy(claim->coswid.entity.entity_name, "");
    claim->coswid.entity.role = 1;
         
    if (claim == NULL){
        return ATTESTATION_ERROR_MEASUREMENTS;
    }
    else{
        return edhoc_initial_attest_encode_measurements(token_buf, claim, token_size);
    }

}

/**
 * @brief collect other infos then create the payload in CBOR
 */
static attestation_status_t edhoc_initial_attest_token_payload (const uint8_t challenge[8], size_t challenge_size, token_t *token, uint8_t *token_buf, uint8_t *token_size){
    memcpy(token->ueid, "aaa", strlen("aaa"));
    memcpy(token->nonce, challenge, challenge_size);

    if (token == NULL){
        return ATTESTATION_ERROR_TOKEN;
    }
    else{
        
        return edhoc_initial_attest_encode_token(token_buf, token, token_size);
    }

}

/**
 * @brief get the signature and transfer it to CBOR
 */
static attestation_status_t edhoc_initial_attest_signature(uint8_t *signature, const uint8_t *data, uint8_t data_size, const uint8_t *private_key, const uint8_t *public_key, uint8_t *token_buf, uint8_t *token_size, uint8_t *protected_header_start, uint8_t *protected_header_end){
//using ed25519
    //construct sig_signature structure
    uint8_t sig_structure = 0;
    uint8_t sig_structure_cbor[MAX_TOKEN];
    sig_structure += cborencoder_put_array(&sig_structure_cbor[sig_structure], 4); //fixed, 4 elements in the array
    sig_structure += cborencoder_put_text(&sig_structure_cbor[sig_structure], "Signature1", strlen("Signature1")); //fixed, use COSE_Sign1

    //get protected header in bytes
    uint8_t protected_header_length = *protected_header_end - *protected_header_start;
    uint8_t protected_header[protected_header_length];
    memcpy(protected_header, &token_buf[*protected_header_start], protected_header_length);
    sig_structure += cborencoder_put_bytes(&sig_structure_cbor[sig_structure], protected_header, protected_header_length); //protected header in bytes
    sig_structure += cborencoder_put_bytes(&sig_structure_cbor[sig_structure], NULL, 0); //external_aad

    //add payload to sig_structure
    memcpy(&sig_structure_cbor[sig_structure], data, data_size);
    printf("sig_structure is: \n");
    for (uint8_t i =0; i < sig_structure+data_size; i++){
    printf("%02x", sig_structure_cbor[i]);
    }
    printf("\n");

    //generate signature
    size_t signature_len = crypto_ed25519_sign (signature, sig_structure_cbor, sig_structure+data_size, private_key, public_key);
    if (signature_len != ED25519_SIGNATURE_LEN){
        return ATTESTATION_ERROR_SIGNATURE;
    } else {
        *token_size += cborencoder_put_bytes(&token_buf[*token_size], signature, ED25519_SIGNATURE_LEN);
    }
    printf("signature is:\n");
    for (uint8_t i = 0; i<ED25519_SIGNATURE_LEN; i++){
          printf("%02x", signature[i]);
        }
    printf("\n");
    return 0;
}

//================================ public =================================

attestation_status_t edhoc_initial_attest_signed_token(const uint8_t *challenge, uint8_t *token_buf, uint8_t *token_size){

//the whole signed token size
*token_size = 0;
uint8_t protected_header_start = 0;
uint8_t protected_header_end = 0;
//headers
status = edhoc_initial_attest_encode_cose_headers(token_buf, token_size, &protected_header_start, &protected_header_end);
if (status!=0){
    printf("error: %d\n", status);
    return status;
}
uint8_t payload_start = *token_size;
uint8_t payload_size = 0;
uint8_t pre_token_buf[MAX_TOKEN];
uint32_t image_size = 0;

//payload encoded in CBOR to be a bstr
status = edhoc_initial_attest_token_payload(challenge, EDHOC_INITIAL_ATTEST_CHALLENGE_SIZE_8, &token, pre_token_buf, &payload_size);
status = edhoc_initial_attest_measurements_cbor(&claim, pre_token_buf, &payload_size);
status = edhoc_initial_attest_get_hashed_image(&_table, hash, &image_size);
status = edhoc_initial_attest_evidence_cbor(&evidence, pre_token_buf, &payload_size, hash, &image_size); 


//payload as a bstr to be encoded
*token_size += cborencoder_put_bytes(&token_buf[*token_size], pre_token_buf, payload_size);

//signature
status = edhoc_initial_attest_signature(signature, &token_buf[payload_start], *token_size-payload_start, private_key, public_key, token_buf, token_size, &protected_header_start, &protected_header_end);
if (status!=0){
    return ATTESTATION_ERROR_SIGNATURE;
}

printf("Final token size: %d\n", *token_size);
printf("The entire token is:\n");
for (uint8_t i = 0; i<*token_size; i++){
        printf("%02x", token_buf[i]);
}
printf("\n");
return ATTESTATION_SUCCESS;
}

