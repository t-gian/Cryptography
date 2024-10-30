#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char **argv){

    if (argc!=2){
        fprintf(stderr, "Invalid parameters. Usage: %s filename \n", argv[0]);
        exit(1);
    }


    char message[] = "This is the message to hash!!";

    FILE *f_in;
    if((f_in = fopen(argv[1],"r"))== NULL){
        fprintf(stderr, "Invalid file\n");
        exit(1);
    }
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    EVP_MD_CTX *md;

    md = EVP_MD_CTX_new();

    EVP_DigestInit(md, EVP_sha1());

    EVP_DigestUpdate(md, message, strlen(message));

    unsigned char md_value[20]; //160 bits long sha1 returns
    unsigned int md_len; //updated by openssl, real final lenght, sould be as up, but just to be sure

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    printf("The digest is: ");
    for(int i=0; i < md_len; i++)
        printf("%02x",md_value[i]);
    printf("\n");
    return 0;
}
