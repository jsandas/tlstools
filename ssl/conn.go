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

type cipherInfo struct {
	cipher      uint16
	name        string
	opensslname string
}

// using a map with an int as the key because the uint
// values of the ciphers is not in order
var cipherSuitesMap = map[int]cipherInfo{
	0:  {TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"},
	1:  {TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
	2:  {TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
	3:  {TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"},
	4:  {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
	5:  {TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ", "DHE-RSA-AES256-GCM-SHA384"},
	6:  {TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "ECDHE-ECDSA-CHACHA20-POLY1305"},
	7:  {TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "ECDHE-RSA-CHACHA20-POLY1305"},
	8:  {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"},
	9:  {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
	10: {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"},
	11: {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"},
	12: {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA"},
	13: {TLS_DHE_RSA_WITH_AES_256_CBC_SHA, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA"},
	14: {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA"},
	15: {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA"},
	16: {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA"},
	17: {TLS_DHE_RSA_WITH_AES_128_CBC_SHA, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA"},
	18: {TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA"},
	19: {TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE-ECDSA-RC4-SHA"},
	20: {TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA"},
	21: {TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384"},
	22: {TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256"},
	23: {TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"},
	24: {TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA"},
	25: {TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA"},
	26: {TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA"},
	27: {TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE-RSA-CAMELLIA256-SHA"},
	28: {TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "CAMELLIA256-SHA"},
	29: {TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA"},
	30: {TLS_RSA_WITH_RC4_128_MD5, "TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5"},
	31: {TLS_RSA_EXPORT_WITH_RC4_40_MD5, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXP-RC4-MD5"},
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	// TLS_FALLBACK_SCSV:                       "FALLBACK_SCSV",
}

func cipherStrList(uList []uint16) []string {
	var cList []string
	for i := range uList {
		for _, v := range cipherSuitesMap {
			if uList[i] == v.cipher {
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
		InsecureSkipVerify: true,
		CipherSuites:       ciphers,
		MinVersion:         uint16(proto),
		MaxVersion:         uint16(proto),
	}

	if ciphers == nil {
		tlsCfg = tls.Config{
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
	for i := range uList {
		for _, v := range cipherSuitesMap {
			if uList[i] == v.cipher {
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

	if service != "https" || strings.HasSuffix(service, "SSL") {
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
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	err = cmd.Run()
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
