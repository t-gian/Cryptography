#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>

#define DECRYPT 0

int base64Decode(char* b64message, unsigned char** buffer) {
    BIO *bio, *b64;
    int decodeLen = strlen(b64message);
    *buffer = (unsigned char*)malloc(decodeLen);
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, *buffer, decodeLen);
    BIO_free_all(bio);
    return decodeLen;
}

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[] = "0123456789ABCDEF";
    const char* algorithm_name = "aria-128-cbc";
    unsigned char* ciphertext;
    int ciphertext_len;
    unsigned char decryptedtext[128];
    int decryptedtext_len;

    char* b64message = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";
    int decodeLen = base64Decode(b64message, &ciphertext);
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit_ex(ctx, EVP_get_cipherbyname(algorithm_name), NULL, key, iv, DECRYPT)) {
        printf("Error in EVP_CipherInit_ex\n");
        return 1;
    }
    if (!EVP_CipherUpdate(ctx, decryptedtext, &decryptedtext_len, ciphertext, decodeLen)) {
        printf("Error in EVP_CipherUpdate\n");
        return 1;
    }
    if (!EVP_CipherFinal(ctx, decryptedtext + decryptedtext_len, &decryptedtext_len)) {
        printf("Error in EVP_CipherFinal\n");
        return 1;
    }
    decryptedtext_len += 16;  // Adding the IV length
    printf("Decrypted Text: %s\n", decryptedtext);
    printf("Flag: CRYPTO24{%s%s}\n", decryptedtext, algorithm_name);
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return 0;
}
