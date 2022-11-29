package ccs

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/ssl"
	"github.com/jsandas/tlstools/pkg/utils/tcputils"
)

const (
	notVulnerable = "no"
	vulnerable    = "yes"
	testFailed    = "error"
)

type CCSInjection struct {
	Vulnerable string `json:"vulnerable"`
}

// CCS test
func (h *CCSInjection) Check(host string, port string, tlsVers int) error {
	conn, err := net.DialTimeout("tcp", host+":"+port, 3*time.Second)
	if err != nil {
		logger.Errorf("event_id=tcp_dial_failed msg=\"%v\"", err)
		h.Vulnerable = testFailed
		return err
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
		h.Vulnerable = testFailed
		return err
	}

	// Send clientHello
	clientHello := makeClientHello(tlsVers)
	err = tcputils.Write(conn, clientHello, 2)
	if err != nil {
		logger.Debugf("event_id=ccs_clientHello_failed msg=\"%v\"", err)
		h.Vulnerable = testFailed
		return err
	}

	connbuf := bufio.NewReader(conn)

	err = readServerHello(connbuf)
	if err != nil {
		switch err.Error() {
		// some applications reset the tcp connection
		// when probing for ccs
		case "EOF":
		default:
			logger.Debugf("event_id=ccs_handshake_failed msg=\"%v\"", err)
			h.Vulnerable = testFailed
			return err
		}
	}

	payload := makePayload(tlsVers)
	err = tcputils.Write(conn, payload, 2)
	if err != nil {
		logger.Debugf("event_id=ccs_payload_failed msg=\"%v\"", err)
		h.Vulnerable = testFailed
		return err
	}

	h.Vulnerable = ccsListen(connbuf)
	return nil

}

func readServerHello(buff *bufio.Reader) error {
	var data []byte

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

	return fmt.Errorf("no serverHello found")
}

// reads from buffer and checks the size of the response
// to determine if heartbleed was exploited
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
			// logger.Debugf("event_id=ccs_error msg=%v", err)
			break
		}

		if len(data) >= 1600 {
			logger.Debugf("event_id=ccs_check status=%s", vulnerable)
			return vulnerable
		}

		i++
	}

	return notVulnerable
}
