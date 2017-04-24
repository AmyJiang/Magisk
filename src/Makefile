OBJ ?=../test_slice/test_slice
PIN ?=/home/amy/repos/pin-3.2-81205-gcc-linux/pin
DIR ?=../test_slice
INPUT ?= input/1.txt
QUERY ?= input/2.txt

all:
		$(MAKE) pintool
		go install ./debugger
		$(MAKE) debugger

pintool:
		$(MAKE) -C ./ExecTrace

debugger:
		go build -o ./bin/debugger debugger

format:
		go fmt ./...
		clang-format --style=file -i ExecTrace/*.cpp

clean:
		$(MAKE) clean  -C ./ExecTrace
		rm -rf ./bin/

test:
		../bin/debugger -bin $(OBJ) -pin $(PIN) -dir $(DIR) -input $(INPUT) -query $(QUERY)

testall:
		../bin/debugger -procs 3 -bin $(OBJ) -pin $(PIN) -dir $(DIR)




