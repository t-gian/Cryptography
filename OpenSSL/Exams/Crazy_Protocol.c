/**
 * The specification of the CRAZY protocol includes the following operations:
 *
 * 1. Generate two strong random 128-bit integers, name them rand1 and rand2
 *
 * 2. Obtain the first key as
 * k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
 *
 * 3. Obtain the second key as
 * k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
 *
 * 4. Encrypt k2 using k1 using a strong symmetric encryption algorithm (and mode) of your choice
 * call it enc_k2.
 *
 * 5. Generate an RSA keypair with a 2048 bit modulus.
 *
 * 6. Encrypt enc_k2 using the just generated RSA key.
 *
 *
 **/
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#define ENCRYPT 1
#define DECRYPT 0
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    BIGNUM *rand1 = BN_new();
    BIGNUM *rand2 = BN_new();

    /* init the random engine: */
    int rc = RAND_load_file("/dev/random", 64);
    if(rc != 64) {
        handle_errors();
    }
    BN_rand(rand1,128,0,1);
    BN_rand(rand2,128,0,1);

    //Step 2
    BN_CTX *ctx=BN_CTX_new();
    BIGNUM *sum = BN_new();
    BIGNUM *diff = BN_new();
    BIGNUM *key1 = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();
    BN_add(sum,rand1,rand2);
    BN_sub(diff, rand1, rand2);
    BN_set_word(base,2);
    BN_set_word(exp,128);
    BN_exp(mod,base,exp,ctx);
    BN_mod_mul(key1,sum,diff,mod,ctx);

    BIGNUM *mult = BN_new();
    BN_mul(mult,rand1,rand2,ctx);
    BIGNUM *key2= BN_new();
    BIGNUM *divs = BN_new();
    BIGNUM *rem = BN_new();
    BN_div(divs,rem,mult,diff,ctx);
    BN_mod(key2,divs,mod,ctx);

    /*Encrypt k2 with AES_128_CBC with k1 -> transform in hex */
    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();

     char *k1_hex = BN_bn2hex(key1);
     char *k2_hex = BN_bn2hex(key2);

    if (!EVP_CipherInit(enc_ctx, EVP_aes_128_cbc(), (unsigned char *) k1_hex, NULL, ENCRYPT))
        handle_errors();
    unsigned char enc_k2[strlen(k2_hex) +16];
    int length,update_len,ciphertext_len = 0;
    int final_len = 0;
    if (!EVP_CipherUpdate(enc_ctx, enc_k2, &update_len, (unsigned char *) k2_hex, strlen(k2_hex))) {
        handle_errors();
    }
    ciphertext_len += update_len;

    if(!EVP_CipherFinal_ex(enc_ctx,enc_k2+ciphertext_len,&final_len)) {
        handle_errors();
    }
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(enc_ctx);
    /* Generate an RSA Keypair with a 2048 bit modulus*/
    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;
    if((rsa_keypair = EVP_RSA_gen(bits)) == NULL )
        handle_errors();
    /*Encyrpt k2 with the just generated keypair*/
    EVP_PKEY_CTX* enc_ctx_rsa = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx_rsa) <= 0) {
        handle_errors();
    }
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx_rsa, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }
    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx_rsa, NULL, &encrypted_msg_len, (unsigned char *) k2_hex, strlen(k2_hex)) <= 0) {
        handle_errors();
    }


    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx_rsa, encrypted_msg, &encrypted_msg_len, (unsigned char *) k2_hex, strlen(k2_hex)) <= 0) {
        handle_errors();
    }
    printf("Final encrypted message is: ");
    for (int i = 0; i < encrypted_msg_len; i++) {
        printf("%02x", encrypted_msg[i]);
    }
    printf("\n");
}

