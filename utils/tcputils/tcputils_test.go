package tcputils

import (
	"errors"
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
		Write(server, b, 2)
		server.Close()
	}()

	out, _ := Read(client, 2)
	client.Close()

	if string(out) != string(b) {
		t.Errorf("wrong data read, got: %s, want: %s", string(out), string(b))
	}
}

func TestReadTimeout(t *testing.T) {
	// 030080 080080 020080
	var b = []byte("hello, this is a read test")
	var expErr = errors.New("io: read/write on closed pipe")

	server, client := net.Pipe()
	go func() {
		Write(server, b, 2)
		server.Close()
	}()

	client.Close()
	_, err := Read(client, 2)

	if errors.Is(err, expErr) {
		t.Errorf("expected error, got: %s, want: %s", err, expErr)
	}
}

func TestGetTCPHeader(t *testing.T) {
	exp := "220 smtp.gmail.com ESMTP"

	out, _ := GetTCPHeader("smtp.gmail.com", "587")

	if !strings.HasPrefix(out, exp) {
		t.Errorf("wrong prefix, got: %s, want: %s", out, exp)
	}
}

func TestGetTCPHeaderError(t *testing.T) {
	var expErr = errors.New("io: read/write on closed pipe")

	_, err := GetTCPHeader("localhost", "587")

	if errors.Is(err, expErr) {
		t.Errorf("expected error, got: %s, want: %s", err, expErr)
	}

}
