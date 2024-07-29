/*
 * Given the envelop_MAC prototype then implement the following transformation:
 *
 * RSA_encrypt(public_key, SHA_256(SHA_256(message || key)))
 *
 * return 0 in case of success, 1 in case of errors, and the result of the RSA encryption by reference
 */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylength, char *result){
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();
    if (!EVP_DigestUpdate(md, message, message_len)) {
        handle_errors();
    }
    if (!EVP_DigestUpdate(md, key, keylength)) {
        handle_errors();
    }
    unsigned char md_value[EVP_MD_get_size(EVP_sha256())];
    int md_len;

    //int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    EVP_DigestFinal(md, md_value, &md_len);
    //resect context
    EVP_MD_CTX_reset(md);
    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();
    if (!EVP_DigestUpdate(md, md_value, message_len)) {
        handle_errors();
    }
    unsigned char md_value_final[EVP_MD_get_size(EVP_sha256())];
    int md_len_final;
    EVP_DigestFinal(md, md_value_final, &md_len_final);

    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        handle_errors();
    }
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }


    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, md_value_final, strlen(md_value_final)) <= 0) {
        handle_errors();
    }


    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, md_value_final, strlen(md_value_final)) <= 0) {
        handle_errors();
    }
    if(encrypted_msg_len == -1) {
        handle_errors();
        return 1;
    }
    //result = &encrypted_msg;
    memcpy(result, encrypted_msg, encrypted_msg_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}