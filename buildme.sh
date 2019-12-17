#!/bin/bash

set +e

TOP=$PWD

cd thirdparty/pcre
./autogen.sh

cd $TOP/flex
./autogen.sh

cd $TOP/thirdparty/oncrpc-ms-code
./bootstrap

cd $TOP

mkdir build
cd build
mkdir pcre
cd pcre

../../thirdparty/configure --host=i686-w64-mingw32 --prefix=$TOP/build

