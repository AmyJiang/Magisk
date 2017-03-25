PIN=/home/amy/repos/pin-3.2-81205-gcc-linux/pin
EXECTRACE=../misc/ExecTrace_test/obj-intel64/exectrace.so
TRACE_DIR=./traces

TEST_CPP=./test.c
TEST_OBJ=./test
TEST_INPUT_DIR=./input

$(TEST_OBJ):
	$(CXX) -ggdb3 -o $(TEST_OBJ) $(TEST_CPP)

.PHONY: run
run: $(TEST_OBJ)
	rm -rf $(TRACE_DIR)
	mkdir -p $(TRACE_DIR)
	@$(foreach input, $(wildcard $(TEST_INPUT_DIR)/*), \
	echo "Running $(input)"; $(PIN) -t $(EXECTRACE) \
	-o $(TRACE_DIR)/$(basename $(notdir $(input))).trace \
	-- $(TEST_OBJ) $(input); )


