# List of SSL libraries
LIBS_DIR=../build
OPENSSL=$(LIBS_DIR)/openssl
LIBRESSL=$(LIBS_DIR)/libressl

LIBS=openssl libressl
CONFIG_USE_LIBS=$(foreach l, \
				$(LIBS), \
				$(-DCONFIG_USE_$(shell echo $l | tr a-z A-Z)))

DBG_MAIN=0
ifeq ($(DBG_MAIN), 1)
CONFIG_DBG_MAIN=-DCONFIG_DBG_MAIN
endif

USE_DER=1
ifeq ($(USE_DER), 1)
CONFIG_USE_DER=-DCONFIG_USE_DER
CA_FORMAT=der
BIN_SUFFIX=.der
else
CONFIG_USE_DER=-DCONFIG_USE_PEM
CA_FORMAT=pem
BIN_SUFFIX=.pem
endif

# CONFIG: Enable debugging logs
DBG_LOG=0
ifeq ($(DBG_LOG), 1)
CONFIG_DEBUG=-DCONFIG_DEBUG
ifeq ($(USE_DER), 1)
BIN_SUFFIX=.der.dbg
else
BIN_SUFFIX=.pem.dbg
endif
else
BIN_SUFFIX=.$(CA_FORMAT)
endif

OPTIONS=$(CONFIG_DBG_MAIN) $(CONFIG_USE_DER) $(CONFIG_DEBUG)
DBGFLAGS=-g -ggdb3
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)

INC_OPENSSL= -I$(OPENSSL)/include
LD_OPENSSL= -L$(OPENSSL)/lib -lcrypto

INC_LIBRESSL= -I$(LIBRESSL)/include
LD_LIBRESSL= -L$(LIBRESSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic

LD_MAIN=-ldl -lstdc++ -lgcrypt -pthread

.PHONY: all
all: mk_all_tests
#
#
# Test rules
#
#

TEST_CERT=test_cert.$(CA_FORMAT)
TEST_COMMON=main_test.cpp

.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

.PHONY: run_all_tests
run_all_tests: $(foreach l, $(LIBS), run_test_$(l))

define mk_tests
test_$1:
	$(CXX) -DCONFIG_TEST_$(shell echo $1 | tr a-z A-Z) \
  -DCONFIG_DBG_MAIN $(CFLAGS) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(TEST_COMMON) $1.cpp -o test_$1$(BIN_SUFFIX) \
	$(LD_$(shell echo $1 | tr a-z A-Z))
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_tests,$(l))) \
)

define mk_run_tests
run_test_$1:
	ASAN_OPTIONS=halt_on_error=0 ./test_$1$(BIN_SUFFIX) \
				 $(CERT_DIR)/$(TEST_CERT)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_run_tests,$(l))) \
)

clean:
	rm -rf *.o *.a *.der *.pem
