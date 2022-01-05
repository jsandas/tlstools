package tcputils

import (
	"net"
	"strings"
	"testing"
)

// this tests both Read and Write functions
func TestReadWrite(t *testing.T) {
	// 030080 080080 020080
	var b = []byte("hello, this is a read test")

	server, client := net.Pipe()
	go func() {
		Write(server, b)
		server.Close()
	}()

	out := Read(client)
	client.Close()

	if string(out) != string(b) {
		t.Errorf("wrong data read, got: %s, want: %s", string(out), string(b))
	}
}

func TestGetTCPHeader(t *testing.T) {
	exp := "220 smtp.gmail.com ESMTP"

	out := GetTCPHeader("smtp.gmail.com", "587")

	if !strings.HasPrefix(out, exp) {
		t.Errorf("wrong prefix, got: %s, want: %s", out, exp)
	}
}
