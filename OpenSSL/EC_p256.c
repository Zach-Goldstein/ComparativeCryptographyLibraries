#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int generate_key() {
    EVP_PKEY *ecc = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;


    int BITS = 2048;

    int err = 0;

    // Generate key
    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        goto free_all;

    if (!(err = EVP_PKEY_paramgen_init(pctx)))
        goto free_all;

    if (!(err = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)))
        goto free_all;

    if (!(err = EVP_PKEY_paramgen(pctx, &params)))
        goto free_all;

    if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
        goto free_all;
    
    if (!(err = EVP_PKEY_keygen_init(kctx)))
        goto free_all;
    
    if (!EVP_PKEY_keygen(kctx, &ecc))
        goto free_all;
    
    // // Write keys to file
    // BIO *b_public = NULL;
    // BIO *b_private = NULL;
    // b_public = BIO_new_file("pubkey.pem", "w+");
    // if (!PEM_write_bio_(b_public, rsa))
    //     goto free_all;
    
    // b_private = BIO_new_file("privkey.pem", "w+");
    // if (!PEM_write_bio_PrivateKey(b_private, ecc, NULL, NULL, 0, NULL, NULL))
    //     goto free_all;

    free_all:
    printf("DONE\n"); fflush(stdout);
    // BIO_free_all(b_public);
    // BIO_free_all(b_private);
    EVP_PKEY_free(params);
    EVP_PKEY_free(ecc);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);

    return err;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}
