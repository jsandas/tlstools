package ssl

import (
	"bytes"
	"crypto/tls"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/jsandas/tlstools/logger"
	"github.com/jsandas/tlstools/utils"
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

	tlsCfg := tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		CipherSuites:       ciphers,
		MinVersion:         uint16(proto),
		MaxVersion:         uint16(proto),
	}

	if ciphers == nil {
		tlsCfg = tls.Config{
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

	client := tls.Client(conn, &tlsCfg)

	err = client.Handshake()
	if err != nil {
		cList := cipherStrList(ciphers)
		logger.Debugf("event_id=tls_dial_failed proto=%s cipher=%v msg\"%v\"", protocolVersionMap[proto].name, cList, err)
		return false
	}

	return true
}

func opensslCString(uList []uint16) string {
	var cList []string
	for _, i := range uList {
		for k, v := range cipherSuites {
			if k == i {
				cList = append(cList, v.opensslname)
			}
		}
	}

	return strings.Join(cList, ":")
}

// opensslDial returns boolean if destination host support specified proto/cipher combo
// this really should only be used for testing sslv3
func opensslDial(host string, port string, proto int, ciphers []uint16) bool {
	path, err := exec.LookPath("openssl")
	if err != nil {
		logger.Warnf("event_id=openssl_not_found")
		return false
	}

	c := ""
	if ciphers != nil {
		c = opensslCString(ciphers)
	}

	s := host + ":" + port
	p := protocolVersionMap[proto].opensslname

	service := utils.GetService(port)

	clientStr := "s_client"
	connectStr := "-connect"
	servernameStr := "-servername"
	cipherStr := "-cipher"
	startTLSStr := "-starttls"

	cmd := exec.Command(path, clientStr, connectStr, s, servernameStr, host, p, cipherStr, c)
	if c == "" {
		// override cmd if c is empty
		cmd = exec.Command(path, clientStr, connectStr, s, servernameStr, host, p)
	}

	if service != "https" && service != "rdp" || strings.HasSuffix(service, "SSL") {
		cmd = exec.Command(path, clientStr, connectStr, s, servernameStr, host, p, cipherStr, c, startTLSStr, service)
		if c == "" {
			// override cmd if c is empty
			cmd = exec.Command(path, clientStr, connectStr, s, servernameStr, host, p, startTLSStr, service)
		}
	}

	// Q closed the connection automatically
	cmd.Stdin = strings.NewReader("Q")
	var out bytes.Buffer
	cmd.Stdout = &out

	// logger.Debugf("event_id=tls_dial proto=%s cipher=%v", protocolVersionMap[proto].name, c)
	err = cmd.Run()
	// fmt.Println(cmd.Stdout)
	if err != nil {
		cList := cipherStrList(ciphers)
		logger.Debugf("event_id=tls_dial_failed proto=%s cipher=%v msg\"%v\"", protocolVersionMap[proto].name, cList, err)
		return false
	}

	return true
}

// OpensslCmd experiment
// func OpensslCmd(host string, port string) {
// 	path, _ := exec.LookPath("openssl")
// 	// if err != nil {
// 	// 	return "openssl not found", err
// 	// }

// 	s := host + ":" + port
// 	cmd := exec.Command(path, clientStr, connectStr, s, servernameStr, host)
// 	cmd.Stdin = strings.NewReader("Q")

// 	stdout, err := cmd.StdoutPipe()
// 	scanner := bufio.NewScanner(stdout)
// 	go func() {
// 		for scanner.Scan() {
// 			fmt.Printf("stdout | %s\n", scanner.Text())
// 			// if scanner.Text() == "Secure Renegotiation IS supported" {
// 			// 	fmt.Printf("stdout | %s\n", scanner.Text())
// 			// }
// 		}
// 	}()

// 	var stderr bytes.Buffer
// 	cmd.Stderr = &stderr

// 	err = cmd.Start()
// 	if err != nil {
// 		fmt.Printf("%s | %v", stderr.String(), err)
// 	}

// 	err = cmd.Wait()
// 	if err != nil {
// 		fmt.Printf("wait: %v", err)
// 	}
// 	// fmt.Printf("%s", stdout.String())
// }
