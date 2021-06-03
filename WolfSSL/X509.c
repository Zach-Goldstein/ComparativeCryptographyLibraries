#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#define WOLFSSL_CERT_GEN
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

RsaKey *load_RSA_key() {
    RsaKey *pkey = NULL;

    byte DER_buf[2048];
    int DER_len = 0;

    char *pem_buf = NULL;
    long pem_len = 0;
    FILE *pem_file = NULL;

    pkey = (RsaKey *)malloc(sizeof(RsaKey));

    wc_InitRsaKey(pkey, NULL);
    
    // Load Private Key into Memory
    if (!(pem_file = fopen("privkey.pem", "r")))
        return NULL;
    
    fseek(pem_file, 0, SEEK_END);
    pem_len = ftell(pem_file);
    fseek(pem_file, 0, SEEK_SET);
    pem_buf = (char *)malloc(pem_len);
    fread(pem_buf, 1, pem_len, pem_file);
    fclose(pem_file);

    if (wc_KeyPemToDer((const unsigned char *)pem_buf, pem_len, DER_buf, 2048, NULL) < 0) {
        free(pem_buf);
        free(pkey);
        return NULL;
    }

    // Load Public Key into Memory
    if (!(pem_file = fopen("pubkey.pem", "r")))
        return NULL;
    
    fseek(pem_file, 0, SEEK_END);
    pem_len = ftell(pem_file);
    fseek(pem_file, 0, SEEK_SET);
    pem_buf = (char *)malloc(pem_len);
    fread(pem_buf, 1, pem_len, pem_file);
    fclose(pem_file);

    // if (wc_KeyPemToDer((const unsigned char *)pem_buf, pem_len, DER_buf, 2048, NULL) < 0) {
    //     free(pem_buf);
    //     free(pkey);
    //     return NULL;
    // }

    free(pem_buf);

    word32 idx = 0;

    if (wc_RsaPrivateKeyDecode(DER_buf, &idx, pkey, 2048)) {
        free(pkey);
        return NULL;
    }

    // if (wc_RsaPublicKeyDecode(DER_buf, &idx, pkey, 2048)) {
    //     free(pkey);
    //     return NULL;
    // }

    printf("PART1 GOOD\n"); fflush(stdout);
    return pkey;
}

int generate_x509() {
    int ret = 0;

    RsaKey *pkey = NULL;
    RNG rng;
    Cert cert;

    pkey = load_RSA_key();
    if (!pkey) {
        ret = -1;
        goto free_all;
    }

    wc_InitRng(&rng);
    wc_InitCert(&cert);

    cert.sigType = CTC_SHA256wRSA;
    
    // Set name
    strncpy(cert.subject.country, "US", CTC_NAME_SIZE);
    strncpy(cert.subject.org, "UVAComputerScience", CTC_NAME_SIZE);
    strncpy(cert.subject.commonName, "localhost", CTC_NAME_SIZE);

    byte derCert[4096];
    int certSz;
    if ((certSz = wc_MakeSelfCert(&cert, derCert, 4096, pkey, &rng)) < 0) {
        ret = -1;
        goto free_all;
    }

    byte pemCert[4096];
    int pemSz;
    if ((pemSz = wc_DerToPem(derCert, certSz, pemCert, 4096, CERT_TYPE)) < 0) {
        ret = -1;
        goto free_all;
    }

    FILE *certToFile;
    if (!(certToFile = fopen("cert.pem", "w"))) {
        ret = -1;
        goto free_all;
    }

    fwrite(pemCert, 1, pemSz, certToFile);
    fclose(certToFile);

    free_all:
    free(pkey);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_x509();
    return err;
}