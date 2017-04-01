CC=gcc
CXX=g++

LIBRESSL=../build/libressl
OPTIONS=-DCONFIG_USE_DER -DCONFIG_DEBUG
DBGFLAGS=-g -ggdb3
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)

LIBRESSL=../build/libressl
INC= -I$(LIBRESSL)/include
LD= -L$(LIBRESSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic


PIN=/home/amy/repos/pin-3.2-81205-gcc-linux/pin
EXECTRACE=../misc/ExecTrace_test/obj-intel64/exectrace.so

TRACE_DIR=./traces
TEST_INPUT_DIR=./input

TEST_CPP=libressl.cpp
TEST_OBJ=./test_libressl


$(TEST_OBJ): $(TEST_CPP)
	$(CXX)  $(CFLAGS) $(INC) $(TEST_CPP) -o $(TEST_OBJ) $(LD)

.PHONY: test
test: $(TEST_OBJ)
	rm -rf $(TRACE_DIR)
	mkdir -p $(TRACE_DIR)
	@$(foreach input, $(wildcard $(TEST_INPUT_DIR)/*), \
	echo "Running $(input)"; $(PIN) -t $(EXECTRACE) \
	-o $(TRACE_DIR)/$(basename $(notdir $(input))).trace \
	-- $(TEST_OBJ) $(input); )


GEN_DIR=./../misc/libressl_man/gen_traces
GEN_INPUT_DIR=./../misc/libressl_man/gen_input

.PHONY: manual_diverg_gen
manual_diverg_gen: $(TEST_OBJ)
	rm -rf $(GEN_DIR)
	mkdir -p $(GEN_DIR)
	@$(foreach input, $(wildcard $(GEN_INPUT_DIR)/*), \
	echo "Running $(input)"; $(PIN) -t $(EXECTRACE) \
	-o $(GEN_DIR)/$(basename $(notdir $(input))).trace \
	-- $(TEST_OBJ) $(input); )


clean:
	rm -rf $(GEN_INPUT_DIR)
	rm -rf $(GEN_DIR)
	rm -rf $(TEST_OBJ)
