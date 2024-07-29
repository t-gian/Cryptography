/**
 * Alice wants to confidentially send Bob the content of a 1MB file through an insecure
 * channel.
 *
 * Write a program in C, using the OpenSSL library, which Alice can execute to send
 * Bob the file.
 *
 * Assume that:
 * - Bob's public key is stored into the RSA *bob_pubkey data structure;
 * - The file to send is available in the FILE *file_in data structure;
 * - Alice cannot establish TLS channels or resort to other protocols
 * - You have access to a high-level communication primitive that sends and receives data
 * and probably format them (e.g., based on a BIO), so that you don't have to think about
 * the communication issues for this exercise
 *
 **/

// Generate symmetric AES-128 key to encrypt with Bob's public key and send it.

#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024
#define MAX_RANDOM 16

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
void send_bob(void *data)
{
    /* helper function that sends the data over the channel */
}


int main(int argc, char **argv){
    if (argc!=3){
        fprintf(stderr,"Invalid parameters. Usage %s file_in file_out \n", argv[0]);
        exit(1);
    }

    // ** Creating the random symmetric key
    unsigned char key[MAX_RANDOM];
    unsigned char IV[MAX_RANDOM];
    if (RAND_load_file("/dev/random", 64)!= 64) // adds to the PRNG, init PRNG.
        handle_errors();
    if (!RAND_bytes(key, MAX_RANDOM)) // RAND_bytes puts MAX random bytes into buffer random_string, error if not CSPRNG.
        handle_errors();
    // ** Creating the random IV
    if (!RAND_bytes(IV, MAX_RANDOM)) // RAND_bytes puts MAX random bytes into buffer random_string, error if not CSPRNG.
        handle_errors();

    // ** Reading file and enciphering it
    FILE *f_in;
    if((f_in = fopen(argv[1],"r"))== NULL){
        fprintf(stderr,"Couldn't open the input file");
        abort();
    }
    FILE *f_out;
    if((f_out = fopen(argv[2],"wb")) == NULL) {
        fprintf(stderr,"Couldn't open the output file, try again\n");
        abort();
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, ENCRYPT))
        handle_errors();

    int length;
    unsigned char ciphertext[MAX_BUFFER+16];
    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while ((n_read = fread(buffer,1, MAX_BUFFER, f_in)) > 0){
        if(!EVP_CipherUpdate(ctx, ciphertext, &length, buffer, n_read))
            handle_errors();
        if (fwrite(ciphertext,1,length,f_out) < length)
            abort();
    }

    if(!EVP_CipherFinal_ex(ctx,ciphertext,&length))
        handle_errors();

    if(fwrite(ciphertext,1,length,f_out) < length)
        abort();

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);
    fclose(f_out);
    //encrypt symmetri ckey
    RSA *bob_pubkey;
    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(bob_pubkey)];

    if((encrypted_data_len = RSA_public_encrypt(strlen(key)+1, key, encrypted_data, bob_pubkey, RSA_PKCS1_OAEP_PADDING)) == -1){
        handle_errors();
    }
    RSA_free(bob_pubkey);
    send_bob(IV);
    send_bob(encrypted_data);
    send_bob(ciphertext);
    return 0;

}





