#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Invalid parameters. Usage: %s file1 file2\n", argv[0]);
        exit(1);
    }

    FILE *f_in1, *f_in2;
    if ((f_in1 = fopen(argv[1], "r")) == NULL || (f_in2 = fopen(argv[2], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input files, try again\n");
        exit(1);
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    EVP_PKEY *pkey;
    unsigned char key[] = "keykeykeykeykeykey";
    unsigned char buffer[MAXBUF];
    unsigned char result[EVP_MAX_MD_SIZE];
    size_t result_len;

    OpenSSL_add_all_algorithms();
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));
    EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey);

    int n;
    while ((n = fread(buffer, 1, MAXBUF, f_in1)) > 0) {
        EVP_DigestSignUpdate(mdctx, buffer, n);
    }
    while ((n = fread(buffer, 1, MAXBUF, f_in2)) > 0) {
        EVP_DigestSignUpdate(mdctx, buffer, n);
    }
    EVP_DigestSignFinal(mdctx, result, &result_len);

    printf("CRYPTO24{");
    for (size_t i = 0; i < result_len; i++)
        printf("%02x", result[i]);
    printf("}\n");

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    fclose(f_in1);
    fclose(f_in2);

    return 0;
}
