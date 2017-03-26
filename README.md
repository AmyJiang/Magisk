Magisk
===========================

## Dependency:

### Pin-3.2

### Go compiler

* Download Go from https://golang.org/dl/ to a directory (e.g. $HOME/go)
* Set the following env variables:
    * export GOROOT=$HOME/go
    * export PATH=$HOME/go/bin:$PATH
    * export GOPATH=$(magisk directory)


## Running debugger

### Building

The following command generates `bin/debugger`
```
$ cd src
$ make

```

```
$ ./bin/debugger --help

Usage of ./bin/debugger:
  -bin string
    	path to fuzzed binary
  -inputdir string
    	directory of input (default ".")
  -pin string
    	path to pin (default "pin")
  -procs int
    	number of parallel processes (default 1)
```

### Running
*   `make test` runs `../bin/debugger -procs 5 -bin $(TEST_OBJ) -pin $(PIN) -inputdir $(INPUT_DIR)`.

*   The debugger runs the test binary with input files from `$(INPUT_DIR)` and
    builds the execution traces into an in-memory prefix tree.

*   To query the first divering point of a diff-inducing input, paste the
    path of this input to debugger stdin. The debugger wil then output the address of the first diverging point.

### Testing
*   Inputs: `test_libressl/corpora`

*   Diff-inducing inputs to check: `test_libressl/out`
















