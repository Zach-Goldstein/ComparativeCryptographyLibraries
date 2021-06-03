#include <gcrypt.h>

int generate_key() {
    int BITS = 2048;

    gcry_error_t err = 0;
    gcry_sexp_t rsakey;
    gcry_sexp_t rsa_params;

    err = gcry_sexp_build(&rsa_params, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err)
        goto free_all;
    
    err = gcry_pk_genkey(&rsakey, rsa_params);
    if (err)
        goto free_all;

    free_all:
    gcry_sexp_release(rsakey);
    gcry_sexp_release(rsa_params);

    return err;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}