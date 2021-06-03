#include <wolfssl/wolfcrypt/sha256.h>

int calculate_hash() {
    int ret = 0;
    char buf[1024];
    unsigned char hash[WC_SHA256_DIGEST_SIZE];

    FILE *file_to_hash;
    if (!(file_to_hash = fopen("to_hash.txt", "r"))) {
        ret = -1;
        goto free_all;
    }

    wc_Sha256 sha256;
    wc_InitSha256(&sha256);
    
    int len = 0;
    while ((len = fread(buf, 1, 1024, file_to_hash)))
        wc_Sha256Update(&sha256, buf, 1024);
    
    wc_Sha256Final(&sha256, hash);

    // int x;
    // for(x = 0; x < WC_SHA256_DIGEST_SIZE; x++)
    //     printf("%02x", hash[x]);
    // putchar( '\n' );

    free_all:
    wc_Sha256Free(&sha256);
    fclose(file_to_hash);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = calculate_hash();
    return 0;
}
