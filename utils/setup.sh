#!/bin/bash
INCL=include.sh
source ${INCL}

OPENSSL_ST=https://www.openssl.org/source/openssl-1.0.2h.tar.gz
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz

sudo apt-get -y install build-essential cmake autogen autoconf
if ! [ -d ${SRC_LIBS}/${OPENSSL} ]; then
    wget -P ${SRC_LIBS} ${OPENSSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${LIBRESSL} ]; then
    wget -P ${SRC_LIBS} ${LIBRESSL_ST} 2>/dev/null
fi
if ! [ -d ${SRC_LIBS}/${NQSB} ]; then
    git clone ${NQSB_ST} ${SRC_LIBS}/nqsb 2>/dev/null
fi

pushd ${SRC_LIBS} >/dev/null
    if [ -f "openssl-1.0.2h.tar.gz" ]; then
        tar xzf "openssl-1.0.2h.tar.gz"
        mv "openssl-1.0.2h" ${OPENSSL}
    fi

    if [ -f libressl-2.4.0.tar.gz ]; then
        tar xzf libressl-2.4.0.tar.gz
        mv libressl-2.4.0 ${LIBRESSL}
    fi
popd > /dev/null

./build_openssl_vanilla.sh
./build_libressl_vanilla.sh

