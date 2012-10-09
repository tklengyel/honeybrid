#!/bin/sh -xe

autoreconf -vi
./configure "$@"
make clean
make
