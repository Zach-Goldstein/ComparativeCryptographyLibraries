#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <stdio.h>

int generate_key() {
    DSA *dsa = NULL;
    BIGNUM *bne = NULL;

    int BITS = 2048;

    int err = 0;
    dsa = DSA_new();
    if (!(err = DSA_generate_parameters_ex(dsa, BITS, NULL, 256, NULL, NULL, NULL)))
        goto free_all;

    if (!(err = DSA_generate_key(dsa)))
        goto free_all;

    // BIO *b_private = NULL;
    // Write keys to file
    // b_private = BIO_new_file("privkey.pem", "w+");
    // if (!PEM_write_bio_DSAPrivateKey(b_private, dsa, NULL, NULL, 0, NULL, NULL))
    //     goto free_all;

    free_all:
    // printf("Done - %i\n", err);
    fflush(stdout);
    // BIO_free(b_private);
    DSA_free(dsa);
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}
