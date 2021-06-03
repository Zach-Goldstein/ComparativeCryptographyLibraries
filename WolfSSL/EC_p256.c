#include <wolfssl/options.h>
#define WOLFSSL_KEY_GEN
#include <wolfssl/wolfcrypt/ecc.h>
// #include <stdio.h>

int generate_key() {
    int curveId = (int)ECC_SECP256R1;
    int BITS = wc_ecc_get_curve_size_from_id(curveId);

    RNG rng;
    wc_InitRng(&rng);

    ecc_key ecc;
    int ret;
    
    if ((ret = wc_ecc_init(&ecc)) < 0)
        goto free_all;
    
    if ((ret = wc_ecc_make_key_ex(&rng, BITS, &ecc, curveId)) < 0)
        goto free_all;

    free_all:
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}