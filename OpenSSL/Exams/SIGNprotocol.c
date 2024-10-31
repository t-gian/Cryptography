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
#include <openssl/pem.h>
#include <string.h>

#define ENCRYPT 1
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{
    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s file_input file_output\n",argv[0]);
        exit(1);
    }
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

    FILE *f_in = fopen(argv[1], "rb");
    if (!f_in) {
        fprintf(stderr, "Error opening input file %s\n", argv[1]);
        return 1;
    }

    FILE *f_out = fopen(argv[2], "wb");
    if (!f_out) {
        fprintf(stderr, "Error opening output file %s\n", argv[2]);
        fclose(f_in);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit(ctx, EVP_aes_256_cbc(), k, NULL, ENCRYPT)) {
        handle_errors();
    }

    int length, n_read;
    unsigned char buffer[MAX_BUFFER], ciphertext[MAX_BUFFER+16]; // max padding

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
    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!rsa_ctx || EVP_PKEY_keygen_init(rsa_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048) <= 0) {
        handle_errors();
    }

    EVP_PKEY *rsa_key = NULL;
    if (EVP_PKEY_keygen(rsa_ctx, &rsa_key) <= 0) {
        handle_errors();
    }
    EVP_PKEY_CTX_free(rsa_ctx);
    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    /* Save key in memory (PEM format) */
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        handle_errors();
    }

    if (PEM_write_bio_PrivateKey(bio_mem, rsa_key, NULL, NULL, 0, NULL, NULL) <= 0) {
        handle_errors();
    }
    EVP_PKEY *rsa_priv_key = PEM_read_bio_PrivateKey(bio_mem, NULL, NULL, NULL);
    if (!rsa_priv_key){
        handle_errors();
    }

    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, rsa_priv_key)) {
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
    
    FILE *sig_file = fopen("signature.bin", "wb");
    if (!sig_file) {
        fprintf(stderr, "Error creating signature file\n");
        handle_errors();
    }
    fwrite(signature, 1, sig_len, sig_file);
    printf("Signature successfully written to signature.bin\n");

    EVP_MD_CTX_free(sign_ctx);

    fclose(f_out);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
