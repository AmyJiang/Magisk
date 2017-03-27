CC=gcc
CXX=g++

LIBRESSL=../build/libressl
OPTIONS=-DCONFIG_USE_DER -DCONFIG_DEBUG
DBGFLAGS=-g -ggdb3
CFLAGS=-O2 -Wall $(DBGFLAGS) $(OPTIONS)

LIBRESSL=../build/libressl
INC= -I$(LIBRESSL)/include
LD= -L$(LIBRESSL)/lib -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic


PIN=/home/hidy/pin-3.2-81205-gcc-linux/pin
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

clean:
	rm $(TEST_OBJ)
