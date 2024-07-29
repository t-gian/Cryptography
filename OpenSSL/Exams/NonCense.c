// The specification of the NONCENSE protocol includes the following operations:
//
// 1) Generate a random 256-bit number, name it r1
// 2) Generate a random 256-bit number, name it r2
// 3) Obtain a key by XOR-ing the two random numbers r1 and r2, name it key_symm
// 4) Generate an RSA keypair of at least 2048 bit modulus
// 5) Encrypt the generated RSA keypair using AES-256 with key_symm and obtain
// 	  the payload.
// Implement in C the protocol steps described above, make the proper decision when
// the protocol omits information.

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#define MAX 32 //occhio che ti dà bits!!! mentre rand_bytes ti torna bytes.

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
int main(){
    unsigned char r1[MAX];
    unsigned char r2[MAX];

//check rand init
    if (RAND_load_file("/dev/random", 64)!= 64) // adds to the PRNG, init PRNG.
        handle_errors();
    if (!RAND_bytes(r1, MAX)) // RAND_bytes puts MAX random bytes into buffer random_string, error if not CSPRNG.
        handle_errors();
    if (!RAND_bytes(r2, MAX)) // RAND_bytes puts MAX random bytes into buffer random_string, error if not CSPRNG.
        handle_errors();
    unsigned char key_simm[MAX];
    for (int i=0; i<strlen(r2);i++){
        key_simm[i] = r1[i]^r2[i];
    }

    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;

    /*
    EVP_PKEY *EVP_RSA_gen(unsigned int bits);
    */
    ;
    if((rsa_keypair = EVP_RSA_gen(bits)) == NULL )
        handle_errors();
    FILE *rsa_private_file = NULL;
    if((rsa_private_file = fopen("private.pem","w")) == NULL) {
        fprintf(stderr,"Couldn't create the private key file.\n");
        abort();
    }
    //aes_256 perche key 256 bits.
    if(!PEM_write_PrivateKey(rsa_private_file, rsa_keypair, EVP_aes_256_cbc(), key_simm, strlen(key_simm), NULL, NULL))
        handle_errors();

    EVP_PKEY_free(rsa_keypair);
    return 0;
}