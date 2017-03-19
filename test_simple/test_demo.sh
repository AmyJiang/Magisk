#!/bin/bash

pushd ../ExecTrace
    make clean > /dev/null 2>1
    make > /dev/null 2>1
popd
make
make run

