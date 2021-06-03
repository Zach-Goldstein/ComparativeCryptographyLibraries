#include <gcrypt.h>

int generate_key() {
    gcry_error_t err = 0;
    gcry_sexp_t ecckey;
    gcry_sexp_t ecc_params;

    err = gcry_sexp_build(&ecc_params, NULL, "(genkey (ecc (curve \"NIST P-256\")))");
    if (err)
        goto free_all;
    
    err = gcry_pk_genkey(&ecckey, ecc_params);
    if (err)
        goto free_all;

    free_all:
    gcry_sexp_release(ecckey);
    gcry_sexp_release(ecc_params);

    return err;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}