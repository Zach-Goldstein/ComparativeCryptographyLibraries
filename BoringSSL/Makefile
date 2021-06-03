CXX=gcc
CXXFLAGS=-g -Wall -Werror -O2 -static

all: RSA_2048 DSA_2048 EC_p256 X509 SHA256 AES_128

RSA_2048: RSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

DSA_2048: DSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

EC_p256: EC_p256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

X509: X509.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

SHA256: SHA256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

AES_128: AES_128.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/home/zngolds/boringssl/build/crypto -lcrypto -pthread

clean:
	rm -f *.o

cleantxt:
	rm -f *.txt

.PHONY: all clean cleantxt
