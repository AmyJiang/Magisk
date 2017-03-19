#!/bin/bash
HL=`tput setaf 1`
RESET=`tput sgr0`

echo "${HL}[+] Building Pintool ExecTrace"
pushd ../ExecTrace > /dev/null
    make clean > /dev/null 2>1
    make > /dev/null 2>1
popd >/dev/null

echo "${HL}[+] Building test_libressl${RESET}"
make clean >/dev/null 2>1
make >/dev/null

echo "${HL}[+] Testing on two certificates: valid.der and invalid.der${RESET}"
echo "    Only difference is a byte changed in Expiration Data field: "
openssl x509 -inform  DER -in input/valid -text -noout > valid.txt
openssl x509 -inform  DER -in input/invalid -text -noout > invalid.txt
diff valid.txt invalid.txt

echo "${HL}[+] Extracting execution paths${RESET}"
make test


