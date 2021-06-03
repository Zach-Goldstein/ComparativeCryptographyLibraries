#include <openssl/blowfish.h>
#include <openssl/evp.h>

static const unsigned char key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char iv[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

int generate_aes() {
    int ret = 0;
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Set enc to 1 for encryption
    EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv, 1);
    EVP_CIPHER_CTX_set_key_length(ctx, 16);

    // Disable padding to make it similar to WolfSSL
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    FILE *file_to_encrypt;
    if (!(file_to_encrypt = fopen("to_hash.txt", "r"))) {
        ret = -1;
        goto free_all;
    }

    FILE *output;
    if (!(output = fopen("bf_output.txt", "w+"))) {
        ret = -1;
        goto free_all;
    }

    for (;;) {
        inlen = fread(inbuf, 1, 1024, file_to_encrypt);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            ret = -1;
            goto free_all;
        }
        fwrite(outbuf, 1, outlen, output);
    }

    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        ret = -1;
        goto free_all;
    }
    fwrite(outbuf, 1, outlen, output);


    free_all:
    fclose(file_to_encrypt);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_aes();
    return err;
}