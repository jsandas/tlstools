package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	logger "github.com/jsandas/gologger"
)

// CanConnect used to confirm host is reachable via tcp
func CanConnect(host string, port string) bool {
	conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
	if err != nil {
		logger.Warnf("event_id=tcp_dial_failed msg=\"%v\"", err)
		return false
	}
	defer conn.Close()

	return true
}

// DownloadBINFile downloads file from url
// and returns as []byte
func DownloadBINFile(uri string) ([]byte, error) {
	buff := new(bytes.Buffer)

	httpRequest, err := http.NewRequest(http.MethodGet, uri, buff)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("host", uri)
	httpRequest.Header.Set("User-Agent", "TLSscanner")

	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   10 * time.Second,
	}
	resp, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buff.ReadFrom(resp.Body)

	return buff.Bytes(), nil
}

// GenRandBytes returns byte array of length n
func GenRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// BytetoInt converts byte slice to integer
func BytetoInt(s []byte) int {
	var b [8]byte
	copy(b[8-len(s):], s)
	return int(binary.BigEndian.Uint64(b[:]))
}

// GetHTTPHeader used to get server header/name
func GetHTTPHeader(host string, port string, name string) (header string) {
	var server = host + ":" + port

	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	httpTransport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsCfg,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   10 * time.Second,
	}

	resp, err := httpClient.Get("https://" + server)
	if err != nil {
		logger.Warnf("event_id=http_client_failed msg=\"%v\"", err)
	}
	header = resp.Header.Get(name)
	logger.Debugf("event_id=retrieved_header name=%s value=%s", name, header)

	return
}

// GetService returns name of service based on port
func GetService(port string) (proto string) {
	switch port {
	case "21":
		proto = "ftp"
	case "25":
		proto = "smtp"
	case "465":
		proto = "smtpSSL"
	case "587":
		proto = "smtp"
	case "110":
		proto = "pop3"
	case "995":
		proto = "pop3SSL"
	case "143":
		proto = "imap"
	case "993":
		proto = "imapSSL"
	case "3389":
		proto = "rdp"
	default:
		proto = "https"
	}

	return
}

// Ltos returns first element of list
// this is to handle certificate information being
// parsed as a string slice
func Ltos(list []string) string {
	value := ""
	if len(list) > 0 {
		value = list[0]
	}
	return value
}

const (
	dnsName string = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`
)

// ValidHost checks for valid hostname
func ValidHost(h string) bool {
	if h == "" || len(strings.Replace(h, ".", "", -1)) > 255 {
		// constraints already violated
		return false
	}

	return regexp.MustCompile(dnsName).MatchString(h)

}

// ValidPort make sure port is in range
func ValidPort(p string) bool {
	i, err := strconv.Atoi(p)
	if err != nil {
		return false
	}
	if !(0 < i && i <= 65535) {
		return false
	}
	return true
}

// WriteFile will write bytes to a file
// This is primarily for debugging
// func WriteFile(file string, input []byte) {
// 	f, err := os.Create(file)
// 	defer f.Close()

// 	if err != nil {
// 		logger.Errorf("file_create_failure: %v", err)
// 	}

// 	_, err = f.Write(input)

// 	if err != nil {
// 		logger.Errorf("file_write_failure: %V", err)
// 	}
// }
