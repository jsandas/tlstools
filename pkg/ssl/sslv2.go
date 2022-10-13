package ssl

import (
	"encoding/hex"
	"net"
	"time"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/utils"
	"github.com/jsandas/tlstools/pkg/utils/tcputils"
)

var sslv2Ciphers = map[string]string{
	"050080": "SSL2_IDEA_128_CBC_WITH_MD5",
	"030080": "SSL2_RC2_128_CBC_WITH_MD5",
	"010080": "SSL2_RC4_128_WITH_MD5",
	"0700c0": "SSL2_DES_192_EDE4_CBC_WITH_MD5",
	"080080": "SSL2_RC4_64_WITH_MD5",
	"060040": "SSL2_DES_64_CBC_WITH_MD5",
	"040080": "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
	"020080": "SSL2_RC4_128_EXPORT40_WITH_MD5",
	"000000": "TLS_NUL_WITH_NULL_NULL",
}

func makeClientHello() []byte {
	var b []byte

	ciphers := ""
	for k := range sslv2Ciphers {
		ciphers = ciphers + k
	}
	length := "8034"
	hello := "01"
	hType := "0002"
	ciphLength := "001b"
	sessID := "0000"
	challength := "0010"
	challenge := "2922beb35a018b04fe5f8003a013ebc4"

	b, _ = hex.DecodeString(length + hello + hType + ciphLength + sessID + challength + ciphers + challenge)

	return b
}

// Check check sslv2 support
func sslv2Check(host string, port string) map[string][]string {
	var connData = make(map[string][]string)

	conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
	if err != nil {
		logger.Errorf("event_id=tcp_dial_failed msg\"%v\"", err)
		return connData
	}
	defer conn.Close()

	err = StartTLS(conn, port)
	if err != nil {
		return connData
	}

	// Send clientHello
	clientHello := makeClientHello()

	err = tcputils.Write(conn, clientHello, 2)
	if err != nil {
		logger.Errorf("event_id=clientHello_send_failed msg\"%v\"", err)
		return connData
	}

	helloB, err := tcputils.Read(conn, 2)
	if err != nil {
		logger.Errorf("event_id=serverHello_read_failed msg\"%v\"", err)
		return connData
	}

	if len(helloB) < 200 {
		logger.Debugf("event_id=serverHello_not_found")
		return connData
	}

	ciphers := sslv2GetCiphers(helloB)

	if len(ciphers) == 0 {
		return connData
	}

	connData["SSLv2"] = ciphers

	logger.Debugf("event_id=sslv2_results msg=\"%v\"", connData)

	return connData
}

func sslv2GetCiphers(bytes []byte) []string {
	var ciphers []string
	cipherSpecLength := utils.BytetoInt(bytes[9:11])
	b := bytes[len(bytes)-(16+cipherSpecLength) : len(bytes)-16]

	for i := 0; i < cipherSpecLength; i = i + 3 {
		cipher := hex.EncodeToString(b[i : i+3])
		ciphers = append(ciphers, sslv2Ciphers[cipher])
	}

	return ciphers
}
