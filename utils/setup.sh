#!/bin/bash
INCL=include.sh
source ${INCL}

OPENSSL_ST=https://www.openssl.org/source/old/1.0.0/openssl-1.0.0i.tar.gz
LIBRESSL_ST=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.0.tar.gz
OCAML_ST=http://caml.inria.fr/pub/distrib/ocaml-4.02/ocaml-4.02.3.tar.gz
NQSB_ST=https://github.com/mirleft/ocaml-x509.git



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
    if [ -f "openssl-1.0.0i.tar.gz" ]; then
        tar xzf "openssl-1.0.0i.tar.gz"
        mv "openssl-1.0.0i" ${OPENSSL}
    fi

    if [ -f libressl-2.4.0.tar.gz ]; then
        tar xzf libressl-2.4.0.tar.gz
        mv libressl-2.4.0 ${LIBRESSL}
    fi
popd > /dev/null

#./build_openssl_vanilla.sh
./build_libressl_vanilla.sh
#./build_nqsb_vanilla.sh


