package certutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
)

func getKeyType(pk interface{}, pka x509.PublicKeyAlgorithm) string {
	k := ""
	keySize := 0

	if pka.String() == "RSA" {
		pubKey := pk.(*rsa.PublicKey)
		keySize = pubKey.Size() * 8
	}
	if pka.String() == "ECDSA" {
		pubKey := pk.(*ecdsa.PublicKey)
		keySize = pubKey.Params().BitSize
	}

	k = fmt.Sprintf("%s-%s", pka.String(), strconv.Itoa(keySize))

	return k
}
