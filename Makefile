CC=gcc

all: evolution-pkcs11.so test

evolution-pkcs11.so: pkcs11.c
	${CC} -I/usr/include/nspr4 -g -shared -fPIC -o evolution-pkcs11.so pkcs11.c

test: test.c evolution-pkcs11.so 
	${CC} -I/usr/include/nspr4  -g -o test test.c ./evolution-pkcs11.so -lnss3 -lplc4 

clean: 
	rm -rf evolution-pkcs11.so test
