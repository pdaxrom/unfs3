#!/bin/bash

set -e

MAKEARGS=-j9

TOP=$PWD

TARGET=i686-w64-mingw32

if test ! -e $TOP/thirdparty/pcre/configure; then
    cd $TOP/thirdparty/pcre
    ./autogen.sh
fi

if test ! -e $TOP/thirdparty/flex/configure; then
    cd $TOP/thirdparty/flex
    ./autogen.sh
fi

if test ! -e $TOP/thirdparty/oncrpc-ms-code/configure; then
    cd $TOP/thirdparty/oncrpc-ms-code
    ./bootstrap
fi

if test ! -e $TOP/configure; then
    cd $TOP
    ./bootstrap
fi

mkdir -p $TOP/build/pcre
cd $TOP/build/pcre

../../thirdparty/pcre/configure --host=$TARGET --prefix=$TOP/build
make $MAKEARGS && make install

ln -sf pcre2posix.h $TOP/build/include/regex.h

mkdir -p $TOP/build/flex
cd $TOP/build/flex

../../thirdparty/flex/configure --host=$TARGET -prefix=$TOP/build CPPFLAGS="-I$TOP/build/include" LDFLAGS="-L$TOP/build/lib"
make $MAKEARGS libfl && make install-libfl

mkdir -p $TOP/build/oncrpc-ms-code
cd $TOP/build/oncrpc-ms-code

../../thirdparty/oncrpc-ms-code/configure  --host=$TARGET -prefix=$TOP/build CPPFLAGS="-I$TOP/build/include" LDFLAGS="-L$TOP/build/lib"
make $MAKEARGS && make install

mkdir -p $TOP/build/unfs3
cd $TOP/build/unfs3

../../configure --host=$TARGET -prefix=$TOP/build CFLAGS="-I$TOP/build/include" LDFLAGS="-L$TOP/build/lib -static-libgcc"

make && make install

echo "done"
