#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>

int generate_key() {
    int BITS = 2048;

    RsaKey genKey;
    RNG rng;
    int ret;
    wc_InitRng(&rng);
    wc_InitRsaKey(&genKey, 0);

    if ((ret = wc_MakeRsaKey(&genKey, BITS, 65537, &rng)) != 0)
        goto free_all;

    free_all:
    wc_FreeRsaKey(&genKey);
    wc_FreeRng(&rng);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_key();
    return err;
}