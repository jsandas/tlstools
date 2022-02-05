package ccs

import (
	"encoding/hex"
	"fmt"

	"github.com/jsandas/tlstools/utils"
)

// tlsv1 = 01
// tlsv1.1 = 02
// tlsv1.2 = 03

func makePayload(tlsVers int) []byte {
	// Create equivalent of this string
	// ccs_payload="\x14\x03\x$TLSV\x00\x01\x01"
	var b []byte

	contentType := "14"                       // ChangeCipherSpec record
	tlsVersion := fmt.Sprintf("0%x", tlsVers) // tls version
	length := "0001"                          // 1 byte
	payload := "01"

	b, _ = hex.DecodeString(contentType + tlsVersion + length + payload)

	// logger.Debugf("ChangeCipherSpec MSG: %X", b)

	return b
}

func makeClientHello(tlsVers int) []byte {
	var b []byte

	rand, _ := utils.GenRandBytes(32)

	contentType := "16"
	tlsVersion := fmt.Sprintf("0%x", tlsVers)
	length := "00dc"
	hsType := "01"
	hsLength := "0000d8"
	hsTLSVersion := fmt.Sprintf("0%x", tlsVers)
	random := hex.EncodeToString(rand)
	everythingElse := "000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"

	b, _ = hex.DecodeString(contentType + tlsVersion + length + hsType + hsLength + hsTLSVersion + random + everythingElse)

	// logger.Debugf("ClientHello: %X", b)
	return b
}
