CXX=gcc
CXXFLAGS=-g -Wall -Werror -O2 -static

all: RSA_2048 DSA_2048 EC_p256 X509 SHA256 AES_128

RSA_2048: RSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

DSA_2048: DSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

EC_p256: EC_p256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

X509: X509.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

SHA256: SHA256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

AES_128: AES_128.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lwolfssl

clean:
	rm -f *.o

cleantxt:
	rm -f *.txt

.PHONY: all clean cleantxt
