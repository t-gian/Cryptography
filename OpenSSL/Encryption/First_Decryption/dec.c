#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    unsigned char key_hex[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv_hex[] = "11111111111111112222222222222222";
    unsigned char ciphertext[] = "8f24b734806a7a7d825a90c8da3912bbecfddcd9036d6914322b60d9";
    int ciphertext_len = strlen(ciphertext);
    int length;
    unsigned char plaintext[ciphertext_len];
    int plaintext_len = 0;

    unsigned char key[strlen(key_hex) / 2];
    for (int i = 0; i < strlen(key_hex) / 2; i++)
    {
        sscanf(&key_hex[2 * i], "%2hhx", &key[i]);
    }

    unsigned char iv[strlen(iv_hex) / 2];
    for (int i = 0; i < strlen(iv_hex) / 2; i++)
    {
        sscanf(&iv_hex[2 * i], "%2hhx", &iv[i]);
    }
    unsigned char real[strlen(ciphertext) / 2];
    for (int i = 0; i < strlen(ciphertext) / 2; i++)
    {
        sscanf(&ciphertext[2 * i], "%2hhx", &real[i]);
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT);

    EVP_CipherUpdate(ctx, plaintext, &length, real, strlen(real));
    plaintext_len += length;

    EVP_CipherFinal_ex(ctx, plaintext + plaintext_len, &length);
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    for (int i = 0; i < plaintext_len; i++)
        printf("%c", plaintext[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}