package heartbleed

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
func Heartbleed(host string, port string, tlsVers int) string {
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
		logger.Errorf("event_id=heartbleed_clientHello_failed msg\"%v\"", err)
		return er
	}

	connbuf := bufio.NewReader(conn)

	hBEnabled, err := checkHandshake(connbuf)
	if err != nil {
		switch err.Error() {
		// some applications reset the tcp connection
		// when probing for heartbleed
		case "EOF":
			return safe
		default:
			logger.Errorf("event_id=heartbleed_handshake_failed msg=\"%v\"", err)
			return er
		}
	}

	if !hBEnabled {
		return na
	}

	payload := makePayload(tlsVers)
	err = tcputils.Write(conn, payload)
	if err != nil {
		logger.Errorf("event_id=heartbleed_payload_failed msg=\"%v\"", err)
		return er
	}

	vuln := heartbeatListen(connbuf)

	return vuln

}

// checks if handshake was successful and if the
// heartbeat extension is enabled
func checkHandshake(buff *bufio.Reader) (bool, error) {
	var data []byte
	var err error

	hBEnabled := false
	for {
		b, err := buff.ReadByte()
		if err != nil {
			return hBEnabled, err
		}

		data = append(data, b)

		// is heartbeat extension enabled?
		if strings.HasSuffix(fmt.Sprintf("%X", data), "000F000101") {
			hBEnabled = true
		}
		// is serverHello finished
		if strings.HasSuffix(fmt.Sprintf("%X", data), "0E000000") {
			break
		}
	}

	return hBEnabled, err
}

// reads from buffer and checks the size of the response
// to determine if heartbleed was exploited
func heartbeatListen(buff *bufio.Reader) string {
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
			logger.Debugf("event_id=heartbleed_error msg=%v", err)
			break
		}

		if len(data) >= 1600 {
			logger.Debugf("event_id=heartbleed_check status=%s", vulnerable)
			return vulnerable
		}

		i++
	}

	return safe
}
