/**
 * 0) the server owns an RSA keypair named rsa_server_main
 * 1) the server generates a fresh new RSA keypair named rsa_server_main
 * 2) the server signs the public key exported from rsa_server_temp with rsa_server_main
 * 3) the server generates a random key and IV of the proper size to be used with AES256 in CBC mode
 * 4) the server encrypts the rsa_server_temp with the newly generated key and IV using AES256 in CBC mode
 */

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <openssl/rand.h>

#define MAXBUFFER 1024
#define ENCRYPT 1
#define MAX_ENC_LEN 1000000

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Already loaded but initialize it anyway for test purpose */
    EVP_PKEY *rsa_server_main;
    if ((rsa_server_main = EVP_RSA_gen(2048)) == NULL) {
        handle_errors();
    }

    EVP_PKEY *rsa_server_temp = NULL;
    if ((rsa_server_temp = EVP_RSA_gen(2048)) == NULL) {
        handle_errors();
    }

    FILE *rsa_public_file = NULL;
    if ((rsa_public_file = fopen("public.pem", "w")) == NULL) {
        fprintf(stderr, "Error");
        abort();
    }

    if (!PEM_write_PUBKEY(rsa_public_file, rsa_server_temp)) {
        handle_errors();
    }

    FILE *rsa_private_file = NULL;
    if ((rsa_private_file = fopen("private.pem", "w")) == NULL) {
        fprintf(stderr, "Error");
        abort();
    }

    if (!PEM_write_PrivateKey(rsa_private_file, rsa_server_main, NULL, NULL, 0, NULL, NULL)) {
        handle_errors();
    }
    fclose(rsa_private_file);

    if ((rsa_private_file = fopen("private.pem", "r")) == NULL) {
        fprintf(stderr, "Error");
        abort();
    }
    EVP_PKEY *private_key = PEM_read_PrivateKey(rsa_private_file, NULL, NULL, NULL);
    fclose(rsa_private_file);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key)) {
        handle_errors();
    }

    size_t n_read;
    unsigned char buffer[MAXBUFFER];
    while ((n_read = fread(buffer, 1, MAXBUFFER, rsa_public_file)) > 0) {
        if (!EVP_DigestSignUpdate(sign_ctx, buffer, n_read)) {
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

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    unsigned char key[32], iv[16];

    if (!RAND_bytes(key, 32)) {
        handle_errors();
    }

    if (!RAND_bytes(iv, 16)) {
        handle_errors();
    }

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit(enc_ctx, EVP_aes_256_cbc(), key, iv, ENCRYPT)) {
        handle_errors();
    }

    unsigned char ciphertext[MAX_ENC_LEN];
    int update_len, final_len, ciphertext_len = 0;

    fclose(rsa_public_file);
    if ((rsa_public_file = fopen("public.pem", "r")) == NULL) {
        fprintf(stderr, "Error");
        abort();
    }

    while ((n_read = fread(buffer, 1, MAXBUFFER, rsa_public_file)) > 0) {
        if (ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(enc_ctx)) {
            fprintf(stderr, "The file to cipher is larger than I can manage\n");
            abort();
        }

        if (!EVP_CipherUpdate(enc_ctx, ciphertext+ciphertext_len, &update_len, buffer, n_read)) {
            handle_errors();
        }
        ciphertext_len += update_len;
    }

    if (!EVP_CipherFinal_ex(enc_ctx, ciphertext+ciphertext_len, &final_len)) {
        handle_errors();
    }

    fclose(rsa_public_file);
    EVP_CIPHER_CTX_free(enc_ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}