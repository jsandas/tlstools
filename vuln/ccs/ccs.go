package ccs

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jsandas/tlstools/logger"
	"github.com/jsandas/tlstools/ssl"
	"github.com/jsandas/tlstools/utils/tcputils"
)

const (
	vulnerable = "yes"
	safe       = "no"
	na         = "n/a"
	er         = "error"
)

// Heartbleed test
func CCSInjection(host string, port string, tlsVers int) string {
	conn, err := net.DialTimeout("tcp", host+":"+port, 3*time.Second)
	if err != nil {
		logger.Errorf("event_id=tcp_dial_failed msg\"%v\"", err)
		return er
	}
	defer conn.Close()

	/*
		only test up to tlsv1.2 because not possible
		with tlsv1.3
	*/
	if tlsVers > tls.VersionTLS12 {
		tlsVers = tls.VersionTLS12
	}

	err = ssl.StartTLS(conn, port)
	if err != nil {
		return er
	}

	// Send clientHello
	clientHello := makeClientHello(tlsVers)
	err = tcputils.Write(conn, clientHello)
	if err != nil {
		logger.Errorf("event_id=ccs_clientHello_failed msg\"%v\"", err)
		return er
	}

	connbuf := bufio.NewReader(conn)

	err = checkHandshake(connbuf)
	if err != nil {
		logger.Errorf("event_id=ccs_handshake_failed msg=\"%v\"", err)
		return er
	}

	// send first CCS
	payload := makePayload(tlsVers)
	err = tcputils.Write(conn, payload)
	if err != nil {
		logger.Errorf("event_id=ccs_payload_failed msg=\"%v\"", err)
		return er
	}
	// send second CCS
	err = tcputils.Write(conn, payload)
	if err != nil {
		logger.Errorf("event_id=ccs_payload_failed msg=\"%v\"", err)
		return er
	}

	vuln := ccsListen(connbuf)

	return vuln

}

// checks if handshake was successful
func checkHandshake(buff *bufio.Reader) error {
	var data []byte
	var err error

	for {
		b, err := buff.ReadByte()
		if err != nil {
			return err
		}

		data = append(data, b)

		// is serverHello finished
		if strings.HasSuffix(fmt.Sprintf("%X", data), "0E000000") {
			break
		}
	}

	return err
}

// reads from buffer and checks the size of the response
// to determine if ccs injection was achieved
func ccsListen(buff *bufio.Reader) string {
	// listen for reply
	// ReadBytes has to be ran one to process started, but
	// it will block if there isn't any data to read
	var data []byte

	go func() {
		buff.ReadByte()
	}()
	time.Sleep(1 * time.Second)

	i := 0
	for {
		buffLeft := buff.Buffered()

		// fmt.Printf("iter: %d left: %d\n", i, buffLeft)
		if buffLeft == 0 && i <= 3 {
			i++
			continue
		}

		if buffLeft == 0 && i > 3 {
			break
		}

		b, err := buff.ReadByte()
		data = append(data, b)
		if err != nil {
			break
		}

		if len(data) >= 1600 {
			logger.Debugf("event_id=ccs_check status=%s", vulnerable)
			return vulnerable
		}

		i++
	}

	return safe
}
