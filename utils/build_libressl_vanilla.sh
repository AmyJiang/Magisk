INCL=./include.sh
source ${INCL}


BDIR=${BUILD_LIBS}/${LIBRESSL}
PATCH=${PATCHES}/libressl_2.4.0_sign.patch
echo $BDIR
echo $SRC_LIBS
echo -e "\t * Building vanilla LibreSSL"
if [ ! -d ${BDIR} ]; then
    mkdir -p ${BDIR}
fi


DF="-DFUZZER_DISABLE_SIGNCHECK -g -ggdb3"
pushd ${SRC_LIBS}/${LIBRESSL} >/dev/null
    echo -e "\t\t - Configuring"
    # clean up just in case
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    # patch if we have not patched already
    patch -p1 -N --dry-run --silent < ${PATCH} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t - Applying patch"
        patch -p1 < ${PATCH} >/dev/null 2>&1
    else
        echo -e "\t\t - Skipping patch - already applied"
    fi
    ./configure --disable-shared --with-pic --prefix=${BDIR} \
--exec-prefix=${BDIR} CFLAGS="$DF"> /dev/null  2>&1
    echo -e "\t\t - Adding dependencies"
    echo -e "\t\t - Compiling"
    make -j10 > /dev/null  2>&1
    echo -e "\t\t - Installing"
    make -j10 install > /dev/null 2>&1
    # clean up for next install
    make -j10 clean > /dev/null 2>&1
    make -j10 distclean > /dev/null 2>&1
    if [ -f ${BDIR}/bin/openssl ] &&
        [ -f ${BDIR}/lib/libssl.a ]; then
        echo -e "\t\t - Testing install..\033[0;32m OK\n"
    else
        echo -e "\t\t - Testing install..\033[0;31m FAILED\n"
    fi
    echo -en "\e[0m"
popd >/dev/null
