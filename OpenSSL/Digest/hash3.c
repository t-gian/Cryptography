#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char secret[] = "this_is_my_secret";

    EVP_DigestInit(md, EVP_sha512());

    int n;
    unsigned char buffer[MAXBUF];
    EVP_DigestUpdate(md, secret, strlen(secret));

    while ((n = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        EVP_DigestUpdate(md, buffer, n);
    }

    EVP_DigestUpdate(md, secret, strlen(secret));

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    printf("CRYPTO24{");
    for (int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("}\n");

    return 0;
}
