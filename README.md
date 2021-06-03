# ComparativeCryptographyLibraries
A collection of short cryptography program samples using different open-source C libraries

Please note that accessing low-level cryptography APIs can be insecure if used improperly. These samples are ideal for other programmers trying to use these libraries for the first time and should never be used in production level code.

## Libraries Used
* OpenSSL (https://github.com/openssl/openssl)
* BoringSSL (a fork of OpenSSL) (https://boringssl.googlesource.com/boringssl/)
* Libgcrypt (https://gnupg.org/software/libgcrypt/index.html)
* wolfSSL (formerly CyaSSL) (https://gnupg.org/software/libgcrypt/index.html)

## Some things that might be helpful
* Typically, OpenSSL uses the most memory (maximum resident set size)
* BoringSSL uses much less memory than OpenSSL despite being a fork of it
* BoringSSL has deprecated much of OpenSSL's insecure functionality, but the API calls are mostly the same
* wolfSSL uses the DER format much more than PEM, it also has a lot of options for reducing the library size upon compilation. This is good if you are working with embedded (though the license is a bit more strict)
* Libgcrypt has a nice API with s-expressions, but cannot be ued for TLS/SSL applications
