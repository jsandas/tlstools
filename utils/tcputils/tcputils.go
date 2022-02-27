package tcputils

import (
	"bufio"
	"net"
	"strings"
	"time"

	"github.com/jsandas/tlstools/logger"
)

// Read data to network conn
func Read(conn net.Conn) []byte {
	var bytes []byte

	buff := bufio.NewReader(conn)
	for {
		b, err := buff.ReadByte()
		bytes = append(bytes, b)
		if err != nil {
			break
		}

		buffLeft := buff.Buffered()
		if buffLeft == 0 {
			break
		}
	}
	return bytes
}

// Write data to network conn
func Write(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// GetTCPHeader reads server name from tcp stream
func GetTCPHeader(host string, port string) (header string) {
	var server = host + ":" + port

	conn, err := net.DialTimeout("tcp", server, 3*time.Second)
	if err != nil {
		logger.Debugf("event_id=tcp_dial_failed server=%s msg\"%v\"", server, err)
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line := string(Read(conn))

	return strings.TrimRight(line, "\r\n")
}
