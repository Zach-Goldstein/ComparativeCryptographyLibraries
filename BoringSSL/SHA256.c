// #include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


int calculate_hash() {
    int ret = 0;
    char buf[1024];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx;

    if (!(ctx = EVP_MD_CTX_new()))
        return -1;

    FILE *file_to_hash;
    if (!(file_to_hash = fopen("to_hash.txt", "r"))) {
        ret = -1;
        goto free_all;
    }

    EVP_DigestInit(ctx, EVP_sha256());
    
    int len = 0;
    while ((len = fread(buf, 1, 1024, file_to_hash)))
        EVP_DigestUpdate(ctx, buf, 1024);
    
    EVP_DigestFinal(ctx, hash, NULL);

    // int x;
    // for(x = 0; x < SHA256_DIGEST_LENGTH; x++)
    //     printf("%02x", hash[x]);
    // putchar( '\n' );

    free_all:
    EVP_MD_CTX_free(ctx);
    fclose(file_to_hash);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = calculate_hash();
    return 0;
}
