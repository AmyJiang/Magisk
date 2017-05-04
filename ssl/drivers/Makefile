CC=gcc
CXX=g++

OPTIONS=-DCONFIG_USE_DER -DCONFIG_SUMMARY
DBGFLAGS=-g -ggdb3
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)

LIBRESSL=$(GOPATH)/builds/libressl
OPENSSL=$(GOPATH)/builds/openssl


INC_OPENSSL= -I$(OPENSSL)/include
LD_OPENSSL= -L$(OPENSSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic -ldl

INC_LIBRESSL= -I$(LIBRESSL)/include
LD_LIBRESSL= -L$(LIBRESSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic -ldl

LIBS = openssl libressl

test_%:
	$(CXX) $(CFLAGS) $(INC_$(shell echo $* | tr a-z A-z)) $*.cpp -o $@ \
    $(LD_$(shell echo $* | tr a-z A-z))

.PHONY: all
all: $(foreach l, $(LIBS),  test_$(l))

clean:
	rm -rf test_*

