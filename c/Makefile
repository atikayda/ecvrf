OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || echo /usr)

CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -O2 -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto

.PHONY: all test clean

all: ecvrf_test

vectors_data.h: ../vectors/vectors.json gen_vectors.py
	python3 gen_vectors.py $< > $@

ecvrf_test: ecvrf.c ecvrf_test.c ecvrf.h vectors_data.h
	$(CC) $(CFLAGS) -o $@ ecvrf.c ecvrf_test.c $(LDFLAGS)

test: ecvrf_test
	./ecvrf_test

clean:
	rm -f ecvrf_test vectors_data.h
