/**
 * The program has to check if the computed mac equals
 * the one passed as the second parameter of the command line
 * the program return 0 if the comparison is successful.
 * The hmac key is stored on the file /keys/hmac_key
 * The mac needs to be computed using hmac-sha256
 *
 **/
#include <stddef.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
#define MAXBUF 1024
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){
    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s filename HMAC\n",argv[0]);
        exit(1);
    }
    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file %s, try again\n", argv[1]);
        exit(1);
    }

    FILE *f_key;
    if((f_key = fopen("./keys/hmac_key","r")) == NULL) {
        fprintf(stderr,"Couldn't open the key file, try again\n");
        exit(1);
    }
    char key_buff[MAXBUF];
    size_t n0;
    if((n0 = fread(key_buff, 1, MAXBUF, f_key)) < 0){
        handle_errors();
    }
    /* convert key from hex to binary */
    unsigned char key[strlen(key_buff)/2];
    for(int i = 0; i < strlen(key_buff)/2;i++){
        sscanf(&key_buff[2*i],"%2hhx", &key[i]);
    }
    size_t n;
    unsigned char buffer[MAXBUF];
    EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();

    if (hmac_ctx == NULL){
      handle_errors();
    }
    /* Compute the HMAC */
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32);
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
        handle_errors();

    while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
        // Returns 1 for success and 0 for failure.
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len = EVP_MD_size(EVP_sha256());

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX_free(hmac_ctx);
   
    /* VERIFICATION PART */
    unsigned char hmac_binary[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &hmac_binary[i]);
    }

    // if( CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0 )
    if( (hmac_len == (strlen(argv[2])/2)) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0))
      { 
        printf("HMAC verification succesful, data integrity is checked\n");
        return 0;
      }
    else
      { printf("HMAC verification failed, check for data integrity failed \n");
        return -1;
      }
}
