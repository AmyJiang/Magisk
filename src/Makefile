OBJ ?=../test_libressl/test_libressl
PIN ?=$(PIN_ROOT)/pin
DIR ?=../test_libressl
INPUT ?= input/1.txt
QUERY ?= input/2.txt

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
		../bin/debugger -bin $(OBJ) -pin $(PIN) -dir $(DIR) -input $(INPUT) -query $(QUERY)

testall:
		../bin/debugger -procs 4 -bin $(OBJ) -pin $(PIN) -dir $(DIR)




