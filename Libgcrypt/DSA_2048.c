#include <gcrypt.h>

int generate_key() {
    int BITS = 2048;

    gcry_error_t err = 0;
    gcry_sexp_t dsakey;
    gcry_sexp_t dsa_params;

    err = gcry_sexp_build(&dsa_params, NULL, "(genkey (dsa (nbits 4:2048)))");
    if (err)
        goto free_all;
    
    err = gcry_pk_genkey(&dsakey, dsa_params);
    if (err)
        goto free_all;

    free_all:
    gcry_sexp_release(dsakey);
    gcry_sexp_release(dsa_params);

    return err;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}