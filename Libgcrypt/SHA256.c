#include <gcrypt.h>

int calculate_hash() {
    int ret = 0;
    char buf[1024];
    unsigned char *hash;

    FILE *file_to_hash;
    if (!(file_to_hash = fopen("to_hash.txt", "r"))) {
        ret = -1;
        goto free_all;
    }

    gcry_md_hd_t sha256;
    gcry_md_open(&sha256, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (!sha256) {
        ret = -1;
        goto free_all;
    }

    int len = 0;
    while ((len = fread(buf, 1, 1024, file_to_hash)))
        gcry_md_write(sha256, buf, 1024);
    
    hash = gcry_md_read(sha256, GCRY_MD_SHA256);

    // unsigned int hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    // int x;
    // for(x = 0; x < hash_len; x++)
    //     printf("%02x", hash[x]);
    // putchar( '\n' );

    free_all:
    gcry_md_close(sha256);
    fclose(file_to_hash);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = calculate_hash();
    return 0;
}
