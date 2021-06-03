CXX=gcc
CXXFLAGS=-g -Wall -Werror -O2 -static

all: RSA_2048 DSA_2048 EC_p256 SHA256 AES_128

RSA_2048: RSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ `libgcrypt-config --libs`

DSA_2048: DSA_2048.o
	$(CXX) $(CXXFLAGS) -o $@ $^ `libgcrypt-config --libs`

EC_p256: EC_p256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ `libgcrypt-config --libs`

SHA256: SHA256.o
	$(CXX) $(CXXFLAGS) -o $@ $^ `libgcrypt-config --libs`

AES_128: AES_128.o
	$(CXX) $(CXXFLAGS) -o $@ $^ `libgcrypt-config --libs`

clean:
	rm -f *.o

cleantxt:
	rm -f *.txt

.PHONY: all clean cleantxt
