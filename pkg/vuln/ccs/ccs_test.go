package ccs

import (
	"net"
	"testing"
	"time"
)

func TestCCS_UT_001_ImmediateFatalAlert(t *testing.T) {
	// CCS-UT-001: Immediate fatal alert after first CCS => no.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		// Send Alert
		alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x01}
		conn.Write(alert)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	vulnerable, status, err := probeVersion(conn, 0x0303)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if status != ProbeStatusNotVulnerable {
		t.Errorf("Expected StatusNotVulnerable, got %s", status)
	}
	if vulnerable {
		t.Errorf("Expected not vulnerable, got true")
	}
}

func TestCCS_UT_002_FatalAlertSecondCCS(t *testing.T) {
	// CCS-UT-002: Fatal alert with different description after second CCS => yes.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		conn.Read(buf) // ClientHello

		// Send ServerHello (fake)
		serverHello := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
		conn.Write(serverHello)

		conn.Read(buf) // CCS1
		conn.Read(buf) // CCS2

		// Send Alert (the "vulnerable" trigger)
		alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x01}
		conn.Write(alert)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	vulnerable, status, err := probeVersion(conn, 0x0303)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Based on the requirement that UT-002 is "yes":
	if !vulnerable {
		t.Errorf("Expected vulnerable, got false. (Status: %s)", status)
	}
}

func TestCCS_UT_003_NonAlertRecordSecondCCS(t *testing.T) {
	// CCS-UT-003: Non-alert record after second CCS => yes.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		conn.Read(buf) // ClientHello

		// Send ServerHello (fake)
		serverHello := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
		conn.Write(serverHello)

		conn.Read(buf) // CCS1
		conn.Read(buf) // CCS2

		// Send Non-Alert (e.g. ChangeCipherSpec or Handshake)
		nonAlert := []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x00}
		conn.Write(nonAlert)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	vulnerable, status, err := probeVersion(conn, 0x0303)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !vulnerable {
		t.Errorf("Expected vulnerable, got false. (Status: %s)", status)
	}
}

func TestCCS_UT_004_ReadTimeout(t *testing.T) {
	// CCS-UT-004: Read timeout during probe => error.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		conn.Read(buf) // ClientHello

		// Send ServerHello (fake)
		serverHello := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
		conn.Write(serverHello)

		// Wait to trigger timeout
		time.Sleep(500 * time.Millisecond)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set a very short timeout
	conn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	vulnerable, status, err := probeVersion(conn, 0x0303)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if status != ProbeStatusError {
		t.Errorf("Expected StatusError, got %s", status)
	}
	if vulnerable {
		t.Errorf("Expected not vulnerable, got true")
	}
}

func TestCCS_UT_005_ConnectionFailure(t *testing.T) {
	// CCS-UT-005: Connection failure => error.

	var c CCSInjection
	err := c.Check("127.0.0.1", "1") // Likely to fail
	if err == nil {
		t.Error("Expected error for invalid port, got nil")
	}
	if c.Vulnerable != "error" {
		t.Errorf("Expected 'error', got %s", c.Vulnerable)
	}
}

func TestCCS_UT_006_ProtocolMismatchThenSSLv3NotVulnerable(t *testing.T) {
	// CCS-UT-006: TLSv1.2 protocol mismatch then SSLv3 not vulnerable => no.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		version := uint16(buf[3])<<8 | uint16(buf[4])

		if version == 0x0303 { // TLS 1.2
			// Send Alert (mismatch)
			alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x01}
			conn.Write(alert)
		} else if version == 0x0300 { // SSLv3
			// Not vulnerable
			alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x01}
			conn.Write(alert)
		}
	}()

	host, port, _ := net.SplitHostPort(l.Addr().String())
	var c CCSInjection
	err = c.Check(host, port)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if c.Vulnerable != "no" {
		t.Errorf("Expected no, got %s", c.Vulnerable)
	}
}

func TestCCS_UT_007_ProtocolMismatchThenSSLv3Vulnerable(t *testing.T) {
	// CCS-UT-007: TLSv1.2 protocol mismatch then SSLv3 vulnerable => yes.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		version := uint16(buf[3])<<8 | uint16(buf[4])

		if version == 0x0303 { // TLS 1.2
			alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x01}
			conn.Write(alert)
		} else if version == 0x0300 { // SSLv3
			// Vulnerable (send non-alert record)
			nonAlert := []byte{0x16, 0x03, 0x00, 0x00, 0x01, 0x00}
			conn.Write(nonAlert)
		}
	}()

	host, port, _ := net.SplitHostPort(l.Addr().String())
	var c CCSInjection
	err = c.Check(host, port)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if c.Vulnerable != "yes" {
		t.Errorf("Expected yes, got %s", c.Vulnerable)
	}
}
