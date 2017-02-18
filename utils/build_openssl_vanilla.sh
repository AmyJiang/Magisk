INCL=include.sh
source ${INCL}

CWD=`pwd`
PATCH=${CWD}/../patches/openssl_1.0.0i_sign.patch
BDIR=${BUILD_LIBS}/${OPENSSL}

echo -e "\t * Building vanilla OpenSSL"
echo $PATCH
echo $BDIR
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi
pushd ${SRC_LIBS}/${OPENSSL} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make clean > /dev/null 2>&1
    make dclean > /dev/null 2>&1
    cp ../../../../src/utils/patches/${PATCH} .
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    rm ${PATCH}
    ./config shared --prefix=${BDIR} \
--openssldir=${BDIR}/openssl # > /dev/null 2>&1
    echo -e "\t\t - Adding dependencies"
    # there is an issue with multiple builds in openssl
    make depend #> /dev/null 2>&1
    echo -e "\t\t - Compiling"
    make #> /dev/null  2>&1
    echo -e "\t\t - Installing"
    make install_sw #> /dev/null 2>&1
    # clean up for next install
    make clean > /dev/null 2>&1
    make dclean > /dev/null 2>&1
popd >/dev/null
