/**
    Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSl library.
    Imagine you have a client CARL that starts communicating with a server SARA.
    CARL initiates the communication and proposes the public parameters.

    Assume you have access to a set of high-level communication primitives that allow
    you to send and receive big numbers and to properly format them (e.g., based on a BIO)
    so that you don't have to think about the communication issues for this exercise.

    void send_to_sara(BIGNUM b)
    BIGNUM receive_from_sara()
    void send_to_carl(BIGNUM b)
    BIGNUM receive_from_carl()

    Finally answer the following question: what CARL and SARA have to do if they want
    to generate an AES-256 key?
*/

/* Carl and Sara agree on p (large prime) and g generator. Carl sends them.
 * Bob selects x (2, p-2)-> and sends B = g^x mod p to Sara,
 * Sara selects y (2, p-2) -> and sends S = g^y mod p to Carl
 * Both will compute g^xy mod p. In order to generate an aes-256 -> need to divide on 32 bytes length (p).
 */
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
void send_to_sara(BIGNUM *b);
BIGNUM* receive_from_sara();
void send_to_carl(BIGNUM *b);
BIGNUM* receive_from_carl();
int main(){

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();

    /* init the random engine: */
    int rc = RAND_load_file("/dev/random", 64);
    if(rc != 64) {
        handle_errors();
    }
    // generate a 32*8 bit prime (a very small one)
    // BN_generate_prime_ex is deprecated in OpenSSL 3.0 use the one below instead (also has a context for more generic generation)
    // int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb, BN_CTX *ctx);
    if (!BN_generate_prime_ex(p, 32*8, 0, NULL, NULL, NULL))
        handle_errors();
    // generate a 32*8 bit prime (a very small one)
    // BN_generate_prime_ex is deprecated in OpenSSL 3.0 use the one below instead (also has a context for more generic generation)
    // int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb, BN_CTX *ctx);
    if (!BN_generate_prime_ex(g, 32*8, 0, NULL, NULL, NULL))
        handle_errors();

    send_to_sara(p);
    send_to_sara(g);

    // Bob selects x
    BIGNUM *x = BN_new();
    BN_rand(x,31*8,0,1);
    //Bob computes B = g^x mod p
    BIGNUM *B = BN_new();
    BN_CTX *ctx=BN_CTX_new();
    if (!BN_mod_exp(B,g,x,p,ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    send_to_sara(B);

    // Sara
    BIGNUM *y = BN_new();
    BN_rand(y,31*8,0,1);
    //Bob computes B = g^x mod p
    BIGNUM *S = BN_new();
    if (!BN_mod_exp(S,g,y,p,ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    send_to_carl(S);
    //Carl
    BIGNUM *S_recv = receive_from_sara();

    BIGNUM *key = BN_new();
    if (!BN_mod_exp(key, S_recv, x, p, ctx)) {
        handle_errors();
    }
    //stessa cosa....

}





