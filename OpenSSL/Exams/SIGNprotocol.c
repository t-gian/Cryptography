/**
 * The specification of the SIGN protocol includes the following operations:
 * - Generate a random 128-bit number, name it r1
 * - Generate a random 128-bit number, name it r2
 * - Concatenate them to obtain a 256-bit AES key name k
 * - Encrypt the content of the FILE *f_in; with AES and k and save it on the file FILE *f_out
 *   (assume both files have been properly opened)
 * - Generate the signature of the encrypted file FILE *f_out with the RSA keypair available
 *   as EVP_PKEY* rsa_key (properly loaded in advance).
 *
 *  Implement the protocol steps above in C, and make the proper decisions when the protocol omits
 *  information.
 **/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <string.h>

#define ENCRYPT 1
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    /* Generate 256-bit AES key k */
    unsigned char r1[16], r2[16], k[32];
    int i;

    if(!RAND_bytes(r1, 16)) {
        handle_errors();
    }

    if(!RAND_bytes(r2, 16)) {
        handle_errors();
    }

    /* concatenate r1||r2 into k */
    memcpy(k, r1, 16);
    memcpy(k + 16, r2, 16);

    /* Already opened */
    FILE *f_in, *f_out;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit(ctx, EVP_aes_256_cbc(), k, NULL, ENCRYPT)) {
        handle_errors();
    }

    int length, n_read;
    unsigned char buffer[MAX_BUFFER], ciphertext[MAX_BUFFER+16];

    while ((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        if (!EVP_CipherUpdate(ctx,ciphertext,&length,buffer,n_read)) {
            handle_errors();
        }

        if (fwrite(ciphertext, 1, length,f_out) < length){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }

    if (!EVP_CipherFinal(ctx, ciphertext, &length)) {
        handle_errors();
    }

    if (fwrite(ciphertext,1, length, f_out) < length){
        fprintf(stderr,"Error writing in the output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);

    /* Sign f_out with RSA */
    rewind(f_out);

    /* Already loaded (it's supposed to be a private key) */
    EVP_PKEY *rsa_key;

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, rsa_key)) {
        handle_errors();
    }

    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_out)) > 0) {
        if (!EVP_DigestUpdate(sign_ctx, buffer, n_read)) {
            handle_errors();
        }
    }

    size_t sig_len;
    if (!EVP_DigestSignFinal(sign_ctx, NULL, &sig_len)) {
        handle_errors();
    }

    unsigned char signature[sig_len];
    if (!EVP_DigestSignFinal(sign_ctx, signature, &sig_len)) {
        handle_errors();
    }

    EVP_MD_CTX_free(sign_ctx);

    fclose(f_out);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}