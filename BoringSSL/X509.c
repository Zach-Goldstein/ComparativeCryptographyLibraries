// #include <stdio.h>
#include <openssl/rsa.h>
// #include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

EVP_PKEY *load_RSA_key() {
    EVP_PKEY *pkey = NULL;
    
    if (!(pkey = EVP_PKEY_new())) {
        return NULL;
    }

    FILE *fp_private = NULL;
    if (!(fp_private = fopen("privkey.pem", "r"))) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (!PEM_read_PrivateKey(fp_private, &pkey, NULL, NULL)) {
        EVP_PKEY_free(pkey);
        fclose(fp_private);
        return NULL;
    }

    fclose(fp_private);

    return pkey;
}

int generate_x509() {
    int ret = 0;

    // Load keys from file
    EVP_PKEY *pkey = NULL;
    if (!(pkey = load_RSA_key())) {
        return -1;
    }

    X509 *cert = NULL;
    
    if (!(cert = X509_new())) {
        ret = -1;
        goto free_all;
    }

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set expiration
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // Set public key
    X509_set_pubkey(cert, pkey);

    // Set name
    X509_NAME *cert_name = X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(cert_name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(cert_name, "O", MBSTRING_ASC, (unsigned char *)"UVAComputerScience", -1, -1, 0);
    X509_NAME_add_entry_by_txt(cert_name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    X509_set_issuer_name(cert, cert_name);

    // Sign certificate
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        ret = -1;
        goto free_all;
    }

    FILE *cert_file = NULL;
    if (!(cert_file = fopen("cert.pem", "wb"))) {
        ret = -1;
        goto free_all;
    }
    
    if (!(ret = PEM_write_X509(cert_file, cert))) {
        fclose(cert_file);
        ret = -1;
        goto free_all;
    }
    
    free_all:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return ret;
}

int main(int argc, char *argv[]) {
    int err = generate_x509();
    return err;
}
