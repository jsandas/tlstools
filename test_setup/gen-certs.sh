#!/bin/bash

CONF_DIR="conf/openssl"
CA_FOLDER="ca"
# CA_SUBJECT="/CN=Self-Signed Root/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
VALID_CERT_SUBJECT="/CN=valid.tlstest.com/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
REVOKED_CERT_SUBJECT="/CN=revoked.tlstest.com/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."

set -x 

ca () {
    local _type=${1:-rsa}
    rm -rf ca-$_type
    mkdir -p ./$CA_FOLDER-$_type/{certs,crl,newcerts,private}
    rm $CA_FOLDER-$_type/index*
    touch $CA_FOLDER-$_type/index.txt
    # touch $CA_FOLDER-$_type/index.txt.attr
    echo 01 > $CA_FOLDER-$_type/crlnumber
    echo 01 > $CA_FOLDER-$_type/serial
    if [[ $_type == "rsa" ]]; then
        openssl req -nodes -x509 -config $CONF_DIR/openssl-$_type.conf -newkey rsa:2048 -keyout $CA_FOLDER-$_type/private/rootca-$_type.key -out $CA_FOLDER-$_type/certs/rootca-$_type.pem -outform PEM -days 7 -subj "/CN=Self-Signed Root RSA/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
        ca_gen_crl $_type
    elif [[ $_type == "ecc" ]]; then
        openssl req -nodes -x509 -config $CONF_DIR/openssl-$_type.conf -newkey ec:<(openssl ecparam -name secp384r1) -keyout $CA_FOLDER-$_type/private/rootca-$_type.key -out $CA_FOLDER-$_type/certs/rootca-$_type.pem -outform PEM -days 7 -subj "/CN=Self-Signed Root ECC/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
        ca_gen_crl $_type
    fi
}

ca_gen_crl () {
    local _type=${1:-rsa}
    openssl ca -config $CONF_DIR/openssl-$_type.conf -gencrl -keyfile $CA_FOLDER-$_type/private/rootca-$_type.key -cert $CA_FOLDER-$_type/certs/rootca-$_type.pem -out $CA_FOLDER-$_type/crl/rootca-$_type.crl.pem
    openssl crl -inform PEM -in $CA_FOLDER-$_type/crl/rootca-$_type.crl.pem -outform DER -out $CA_FOLDER-$_type/crl/rootca-$_type.crl
    rm $CA_FOLDER-$_type/crl/rootca-$_type.crl.pem
}
ca_sign () {
    local _cert=$1
    local _type=${2:-rsa}
    openssl ca -batch -config $CONF_DIR/openssl-$_type.conf -in $_cert-$_type.csr -days 7 -extfile <(printf "subjectAltName=DNS:$_cert-$_type.tlstest.com")
    rm $_cert-$_type.csr
}

ca_revoke () {
    local _cert=$1
    local _type=${2:-rsa}
    openssl ca -config $CONF_DIR/openssl-$_type.conf -revoke ca-$_type/newcerts/$_cert.pem
    ca_gen_crl $_type
    cp $CA_FOLDER-$_type/crl/rootca-$_type.crl ../pkg/ssl/status/testrevocationfiles/test.crl
}
echo " created certificate authorities..."
ca rsa
if [ $? != 0 ]; then
    echo "something when wrong creating ca-rsa"
    exit 1
fi

ca ecc
if [ $? != 0 ]; then
    echo "something when wrong creating ca-ecc"
    exit 1
fi

echo " generating certs..."

# Generate RSA certs
_type=rsa
openssl genrsa -out valid-$_type.key 2048 
openssl req -config $CONF_DIR/openssl-$_type.conf -out valid-$_type.csr -key valid-$_type.key -new -sha256 -subj "$VALID_CERT_SUBJECT"
ca_sign valid $_type

_type=rsa
openssl genrsa -out revoked-$_type.key 2048 
openssl req -config $CONF_DIR/openssl-$_type.conf -out revoked-$_type.csr -key revoked-$_type.key -new -sha256 -subj "$REVOKED_CERT_SUBJECT"
ca_sign revoked $_type
ca_revoke 01 $_type

# Generate ECC certs
_type=ecc
openssl ecparam -name prime256v1 -genkey -noout -out valid-$_type.key
# openssl genrsa -out valid-$_type.key 2048 
openssl req -config $CONF_DIR/openssl-$_type.conf -out valid-$_type.csr -key valid-$_type.key -new -sha256 -subj "$VALID_CERT_SUBJECT"
ca_sign valid $_type