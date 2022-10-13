package ssl

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/jsandas/etls"
	logger "github.com/jsandas/gologger"
)

func cipherStrList(uList []uint16) []string {
	var cList []string
	for _, i := range uList {
		for k, v := range cipherSuites {
			if k == i {
				cList = append(cList, v.name)
			}
		}
	}
	return cList
}

// ConnState returns list of x509 certificates
func ConnState(host string, port string) (connState tls.ConnectionState, tlsv int) {
	var server = host + ":" + port

	tlsCfg := tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	conn, err := net.DialTimeout("tcp", server, 3*time.Second)
	if err != nil {
		logger.Debugf("event_id=tcp_dial_failed server=%s msg\"%v\"", server, err)
		return
	}
	defer conn.Close()

	err = StartTLS(conn, port)
	if err != nil {
		return
	}

	client := tls.Client(conn, &tlsCfg)

	err = client.Handshake()
	if err != nil {
		logger.Errorf("event_id=connection_state_failed msg=\"%v\"", err.Error())
		return
	}

	return client.ConnectionState(), int(client.ConnectionState().Version)
}

// serverDial returns boolean if destination host support specified proto/cipher combo
func serverDial(host string, port string, proto int, ciphers []uint16) (connected bool) {
	var server = host + ":" + port

	tlsCfg := etls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		CipherSuites:       ciphers,
		MinVersion:         uint16(proto),
		MaxVersion:         uint16(proto),
	}

	if ciphers == nil {
		tlsCfg = etls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         uint16(proto),
			MaxVersion:         uint16(proto),
		}
	}

	conn, err := net.DialTimeout("tcp", server, 3*time.Second)
	if err != nil {
		logger.Debugf("event_id=tcp_dial_failed server=%s msg\"%v\"", server, err)
		return
	}
	defer conn.Close()

	err = StartTLS(conn, port)
	if err != nil {
		return
	}

	client := etls.FakeClient(conn, &tlsCfg)

	err = client.FakeHandshake()
	if err != nil {
		cList := cipherStrList(ciphers)
		logger.Debugf("event_id=tls_dial_failed proto=%s cipher=%v msg\"%v\"", protocolVersionMap[proto], cList, err)
		return false
	}

	return true
}
