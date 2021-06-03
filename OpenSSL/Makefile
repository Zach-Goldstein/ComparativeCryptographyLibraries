CXX=gcc
CXXFLAGS=-g -Wall -Werror -O2 -static

all: RSA_2048 DSA_2048 EC_p256 X509 SHA256

RSA_2048: RSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

DSA_2048: DSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

EC_p256: EC_p256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

X509: X509.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

SHA256: SHA256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

AES_128: AES_128.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcrypto

clean:
	rm -f *.o

cleantxt:
	rm -f *.txt

.PHONY: all clean cleantxt
