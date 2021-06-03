#include <gcrypt.h>

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
    unsigned char *inbuf;
    unsigned char *outbuf;
    int len;
    gcry_cipher_hd_t aes;

    gcry_cipher_open(&aes, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (!aes) {
        return -1;
    }

    // Set key and iv
    gcry_cipher_setkey(aes, key, 16);
    gcry_cipher_setiv(aes, iv, 16);

    FILE *file_to_encrypt;
    if (!(file_to_encrypt = fopen("to_hash.txt", "r"))) {
        ret = -1;
        goto free_all;
    }

    fseek(file_to_encrypt, 0, SEEK_END);
    len = ftell(file_to_encrypt);
    fseek(file_to_encrypt, 0, SEEK_SET);

    inbuf = (unsigned char *)malloc(len);
    outbuf = (unsigned char *)malloc(len);

    if (gcry_cipher_encrypt(aes, outbuf, len, inbuf, len) != 0) {
        ret = -1;
        goto free_all;
    }

    FILE *output;
    if (!(output = fopen("aes_output.txt", "w+"))) {
        ret = -1;
        goto free_all;
    }

    fwrite(outbuf, 1, len, output);
    fclose(output);

    free_all:
    gcry_cipher_close(aes);
    fclose(file_to_encrypt);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_aes();
    return err;
}