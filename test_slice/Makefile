PIN=$(PIN_ROOT)/pin
EXECTRACE=../misc/ExecTrace_test/obj-intel64/exectrace.so
TRACE_DIR=./traces

TEST_CPP=./test_slice.c
TEST_OBJ=./test_slice
TEST_INPUT_DIR=./input

$(TEST_OBJ):
	$(CXX) -ggdb3 -o $(TEST_OBJ) $(TEST_CPP)

.PHONY: test
test: $(TEST_OBJ)
	rm -rf $(TRACE_DIR)
	mkdir -p $(TRACE_DIR)
	@$(foreach input, $(wildcard $(TEST_INPUT_DIR)/*), \
	echo "Running $(input)"; $(PIN) -t $(EXECTRACE) \
	-o $(TRACE_DIR)/$(basename $(notdir $(input))).trace \
	-- $(TEST_OBJ) $(input); )

.PHONY: trace
trace: $(TEST_OBJ)
	rm -rf $(TRACE_DIR)
	mkdir -p $(TRACE_DIR)
	@$(foreach input, $(wildcard $(TEST_INPUT_DIR)/*), \
	echo "Running $(input)"; $(PIN) -t $(EXECTRACE) \
	-o $(TRACE_DIR)/$(basename $(notdir $(input))).trace -mem 1 \
	-- $(TEST_OBJ) $(input); )


.PHONY: clean
clean:
	rm test_slice traces/* slices/*
