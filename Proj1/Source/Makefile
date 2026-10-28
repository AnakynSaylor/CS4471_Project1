all: RBFGen IPCheck

IPCheck: IPCheck.c
	gcc IPCheck.c util/sha256.c -o IPCheck

RBFGen: RBFGen.c
	gcc RBFGen.c util/sha256.c -o RBFGen

clean:
	rm RBFGen IPCheck