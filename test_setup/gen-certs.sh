#!/bin/bash

CONF_DIR="conf/openssl"
CA_FOLDER="ca"
CA_SUBJECT="/CN=Self-Signed Root/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
VALID_CERT_SUBJECT="/CN=valid.tlstest.com/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."
REVOKED_CERT_SUBJECT="/CN=revoked.tlstest.com/C=US/ST=WA/L=Somewhere City/O=Self-Signed Inc."

set -x 

ca () {
    rm -rf ca
    mkdir -p ./$CA_FOLDER/{certs,crl,newcerts,private}
    rm $CA_FOLDER/index*
    touch $CA_FOLDER/index.txt
    # touch $CA_FOLDER/index.txt.attr
    echo 01 > $CA_FOLDER/crlnumber
    echo 01 > $CA_FOLDER/serial
    openssl req -nodes -x509 -config $CONF_DIR/openssl.conf -newkey rsa:2048 -keyout $CA_FOLDER/private/rootca.key -out $CA_FOLDER/certs/rootca.pem -outform PEM -days 7 -subj "$CA_SUBJECT"
    ca_gen_crl
}

ca_gen_crl () {
    openssl ca -config $CONF_DIR/openssl.conf -gencrl -keyfile $CA_FOLDER/private/rootca.key -cert $CA_FOLDER/certs/rootca.pem -out $CA_FOLDER/crl/rootca.crl.pem
    openssl crl -inform PEM -in $CA_FOLDER/crl/rootca.crl.pem -outform DER -out $CA_FOLDER/crl/rootca.crl
    rm $CA_FOLDER/crl/rootca.crl.pem
    cp $CA_FOLDER/crl/rootca.crl ../ssl/status/testrevocationfiles/test.crl
}
ca_sign () {
    CERT=$1
    openssl ca -batch -config $CONF_DIR/openssl.conf -in $CERT.csr -days 7 -extfile <(printf "subjectAltName=DNS:$CERT.tlstest.com")
    rm $CERT.csr
}

ca_revoke () {
    CERT=$1
    openssl ca -config $CONF_DIR/openssl.conf -revoke ca/newcerts/$CERT.pem
    ca_gen_crl
}
echo " created ca..."
ca
if [ $? != 0 ]; then
    echo "something when wrong creating ca"
    exit 1
fi

echo " generating certs..."

openssl genrsa -out valid.key 2048 
openssl req -config $CONF_DIR/openssl.conf -out valid.csr -key valid.key -new -sha256 -subj "$VALID_CERT_SUBJECT"
ca_sign valid

openssl genrsa -out revoked.key 2048 
openssl req -config $CONF_DIR/openssl.conf -out revoked.csr -key revoked.key -new -sha256 -subj "$REVOKED_CERT_SUBJECT"
ca_sign revoked
ca_revoke 01