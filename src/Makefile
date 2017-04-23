TEST_OBJ=../test_libressl/test_libressl
PIN=/home/amy/repos/pin-3.2-81205-gcc-linux/pin
INPUT_DIR=../test_libressl/simple_input

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
		$(MAKE)
		../bin/debugger -procs 5 -bin $(TEST_OBJ) -pin $(PIN) -inputdir $(INPUT_DIR)


