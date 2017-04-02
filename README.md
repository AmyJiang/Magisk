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
*   Original corpus: `test_libressl/corpora`

*   Normal inputs: `test_libressl/input`
    * Format: `(1)_BeforeMutationWas_(2)`
        * (1) is the hash of the certificate after mutation
        * (2) is the hash of the certificate before mutation (e.g. this file)

*   Diff-inducing inputs to check (OpenSSL vs LibreSsl): `test_libressl/diffs`
    * Filename format: `(1)_(2)_(3)_(4)_(5)_(6)`
        * (1), (2) are output from OpenSSL and LibreSSL on the same input
          certificate
            * 0: the certificate is valid
            * Other number: the first 2 chars represent the error code in hex (see the full list in `common.h`)
        * (6): sha1 hash of the input certificate (you can use this value to
          find the input before mutation in `test_libressl/input`)

* One way to test is to use `test_libressl/input` as input directory and check
  the files in`test_libressl/diffs`. Currently there are 43 diffs: OpenSSL
  validates all of them, but LibreSSL rejects and outputs 4 kinds of error code:
  0x14, 0x6, 0xd, 0xe. // Hidy & JiaYan: can you each check on two kinds of
  error?
  
### Trick for navigating in vim
Run
```
sudo apt install cscope
```
Go to the base dir of the project and run
```
cscope -Rb
```
Then add the following lines in your .vimrc:

```
"cscope config
"set cscopequickfix=s-,c+,d+,i+,t+,e+
if has("cscope")
    set csprg=/usr/bin/cscope
    set csto=1
    set cst
    set nocsverb
    set cspc=0
    "add any database in current dir
    if filereadable("cscope.out")
        cs add cscope.out
    "else search cscope.out elsewhere
    else
       let cscope_file=findfile("<path to magisk>/libs/libressl/cscope.out", ".;")
        "echo cscope_file
        if !empty(cscope_file) && filereadable(cscope_file)
            exe "cs add" cscope_file
        endif
     endif
endif

function! Csc()
    cscope find c <cword>
    copen
endfunction
command! Csc call Csc()
```
Now if you place your cursor on top of a function and type ```:Csc<enter>``` its callers will be displayed.
