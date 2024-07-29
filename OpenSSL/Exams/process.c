// A server is listening on a given port where it receives raw bytes
// When a client establishes a connection and sends some data, the server calls
// its internal function process(), which produces the output to send back to the
// client. The prototype of the function is the following one:

// char *process(char *data, int length, RSA *rsa_priv_key)

// The function process():
// Checks if data can be decrypted with rsa_priv_key; if possible,
// obtains decrypted_data by decrypting the data variable (by "manually" implementing
// the RSA decryption algorithm);
// Computes the hash h of decrypted_data using SHA256

// If data can be decrypted, process() returns three bytes:

// As a first byte, the least significant bit of decrypted_data
// As a second byte, the least significant bit of the hash h;
// As a third byte, the XOR of the previous two bytes

// Otherwise, it returns NULL.

// Implement in C the function process() described above using the OpenSSL library.

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

char *process(char *data, int length, RSA *rsa_priv_key)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* m^d mod n */
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, data);

    const BIGNUM *d = RSA_get0_d(rsa_priv_key);
    const BIGNUM *n = RSA_get0_n(rsa_priv_key);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *res = BN_new();

    if (!BN_mod_exp(res, m, d, n, ctx)) {
        return NULL;
    }

    char *decrypted_data = BN_bn2hex(res);
    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    unsigned int md_len;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit(md, EVP_sha256());

    EVP_DigestUpdate(md, decrypted_data, strlen(decrypted_data));
    EVP_DigestFinal_ex(md, md_value, &md_len);
    EVP_MD_CTX_free(md);

    char *rc = malloc(3 * sizeof(char));
    rc[0] = decrypted_data[strlen(decrypted_data)-1];
    rc[1] = md_value[md_len-1];
    rc[2] = rc[0]^rc[1];

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return rc;
}