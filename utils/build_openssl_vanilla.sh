INCL=include.sh
source ${INCL}

BDIR=${BUILD_LIBS}/${OPENSSL}
PATCH=${PATCHES}/openssl_1.0.2h_sign.patch

echo -e "\t * Building vanilla OpenSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi

DF="-DFUZZER_DISABLE_SIGNCHECK -g -ggdb3"
pushd ${SRC_LIBS}/${OPENSSL} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make clean > /dev/null 2>&1
    make dclean > /dev/null 2>&1
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    CC="gcc $DF" ./config no-shared -fPIC --prefix=${BDIR} \
        --openssldir=${BDIR}/openssl > /dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    # there is an issue with multiple builds in openssl
    make depend > /dev/null 2>&1
    echo -e "\t\t - Compiling"
    make #> /dev/null  2>&1
    echo -e "\t\t - Installing"
    make install > /dev/null 2>&1
    # clean up for next install
    make clean > /dev/null 2>&1
    make dclean > /dev/null 2>&1
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
