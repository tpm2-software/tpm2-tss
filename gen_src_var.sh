#!/bin/bash

FILES1=$(<files.txt)
FILES2=`git ls-files`

if [[ $FILES1 != $FILES2 ]]; then
    `git ls-files > files.txt`
    ./bootstrap && make clean
fi
