OBJ ?=../test_libressl/test_libressl
PIN ?=$(PIN_ROOT)/pin
DIR ?=../test_libressl
INPUT ?= simple_input/valid
QUERY ?= simple_input/invalid

all:
		$(MAKE) pintool
		go install ./debugger
		go install ./displayer
		$(MAKE) debugger
		$(MAKE) displayer

pintool:
		$(MAKE) -C ./ExecTrace

debugger:
		go build -o ./bin/debugger debugger

displayer:
		go build -o ./bin/displayer displayer

format:
		go fmt ./...
		clang-format --style=file -i ExecTrace/*.cpp

clean:
		$(MAKE) clean  -C ./ExecTrace
		rm -rf ./bin/

test:
		../bin/debugger -bin $(OBJ) -pin $(PIN) -dir $(DIR) -input $(INPUT) -query $(QUERY) -log -slice

testall:
		../bin/debugger -procs 4 -bin $(OBJ) -pin $(PIN) -dir $(DIR) -log -slice



