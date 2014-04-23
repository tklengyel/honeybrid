#!/bin/sh -xe

autoreconf -vi
./configure "$@"
