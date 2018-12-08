all: build

build:
	mkdir -p bin
	gcc -c -Wall -o bin/rpass-cryptlib.o rpass-cryptlib.c
	ar rcs bin/rpass-cryptlib.a bin/rpass-cryptlib.o

clean:
	rm -rf ./bin
	rm -rf ./testing

test: build
	gcc -o bin/a.out main.c ./bin/rpass-cryptlib.a -lsodium
	mkdir -p testing
	dd if=/dev/urandom of=./testing/plain bs=1K iflag=count_bytes count=10M
	./bin/a.out
	b2sum ./testing/*
