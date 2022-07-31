package tcputils

import (
	"bufio"
	"net"
	"strings"
	"time"

	logger "github.com/jsandas/gologger"
)

// Read data to network conn
func Read(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var bytes []byte

	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
	buff := bufio.NewReader(conn)
	for {
		b, err := buff.ReadByte()
		bytes = append(bytes, b)
		if err != nil {
			return bytes, err
		}

		buffLeft := buff.Buffered()
		if buffLeft == 0 {
			break
		}
	}
	return bytes, nil
}

// Write data to network conn
func Write(conn net.Conn, data []byte, timeout time.Duration) error {
	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))

	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// GetTCPHeader reads server name from tcp stream
func GetTCPHeader(host string, port string) (string, error) {
	var header string

	server := host + ":" + port

	conn, err := net.DialTimeout("tcp", server, 3*time.Second)
	if err != nil {
		logger.Debugf("event_id=tcp_dial_failed server=%s msg\"%v\"", server, err)
		return header, err
	}
	defer conn.Close()

	line, _ := Read(conn, 2)

	header = strings.TrimRight(string(line), "\r\n")

	return header, nil
}
