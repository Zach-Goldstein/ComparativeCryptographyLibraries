// #include <stdio.h>
#include <openssl/rsa.h>
// #include <openssl/bio.h>
#include <openssl/pem.h>

int generate_key() {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    // BIO *b_public = NULL, *b_private = NULL;

    int BITS = 2048;
    unsigned long e = RSA_F4;

    int err = 0;

    // Generate key
    bne = BN_new();
    if (!(err = BN_set_word(bne, e)))
        goto free_all;
    
    rsa = RSA_new();
    if (!(err = RSA_generate_key_ex(rsa, BITS, bne, NULL)))
        goto free_all;

    // // Write keys to file
    // b_public = BIO_new_file("pubkey.pem", "w+");
    // if (!PEM_write_bio_RSAPublicKey(b_public, rsa))
    //     goto free_all;
    
    // b_private = BIO_new_file("privkey.pem", "w+");
    // if (!PEM_write_bio_RSAPrivateKey(b_private, rsa, NULL, NULL, 0, NULL, NULL))
    //     goto free_all;

    free_all:
    // BIO_free_all(b_public);
    // BIO_free_all(b_private);
    RSA_free(rsa);
    BN_free(bne);
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return 0;
}
