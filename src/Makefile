#TEST_OBJ=../test_simple/test
TEST_OBJ=../test_libressl/test_libressl
PIN=/home/amy/repos/pin-3.2-81205-gcc-linux/pin
INPUT_DIR=../test_libressl/input
#INPUT_DIR=../test_simple/input

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

clean:
		$(MAKE) clean  -C ./ExecTrace
		rm -rf ./bin/

test:
		../bin/debugger -procs 5 -bin $(TEST_OBJ) -pin $(PIN) -inputdir $(INPUT_DIR)


