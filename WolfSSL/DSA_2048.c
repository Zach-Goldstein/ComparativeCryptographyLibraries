#include <wolfssl/options.h>
#define WOLFSSL_KEY_GEN
#undef NO_DSA
#include <wolfssl/wolfcrypt/dsa.h>
#include <stdio.h>

int generate_key() {
    int BITS = 2048;

    DsaKey dsakey;
    RNG rng;
    int ret;
    wc_InitRng(&rng);
    wc_InitDsaKey(&dsakey);

    wc_MakeDsaParameters(&rng, BITS, &dsakey);

    if ((ret = wc_MakeDsaKey(&rng, &dsakey)) != 0)
        goto free_all;

    free_all:
    wc_FreeDsaKey(&dsakey);
    wc_FreeRng(&rng);
    return 0;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}