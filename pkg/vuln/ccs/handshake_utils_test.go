package ccs

import (
	"bytes"
	"net"
	"testing"
)

// mockConn implements net.Conn for testing purposes.
type mockConn struct {
	net.Conn
	reader *bytes.Reader
	writer *bytes.Buffer
}

func (m *mockConn) Read(p []byte) (n int, err error)  { return m.reader.Read(p) }
func (m *mockConn) Write(p []byte) (n int, err error) { return m.writer.Write(p) }
func (m *mockConn) Close() error                      { return nil }

func TestMakeClientHello(t *testing.T) {
	version := uint16(0x0303) // TLS 1.2
	record := makeClientHello(version)

	if len(record) < 5 {
		t.Fatalf("record too short: %d", len(record))
	}

	// Check ContentType
	if record[0] != 0x16 {
		t.Errorf("expected content type 0x16, got %x", record[0])
	}

	// Check Version
	if uint16(record[1])<<8|uint16(record[2]) != version {
		t.Errorf("expected version %x, got %x%x", version, record[1], record[2])
	}

	// Check Length field in record
	length := uint16(record[3])<<8 | uint16(record[4])
	if int(length) != len(record)-5 {
		t.Errorf("expected length %d, got %d", len(record)-5, length)
	}
}

func TestReadRecord(t *testing.T) {
	// Sample TLS record: [0x16][0x03][0x03][0x00][0x02][0x01][0x02]
	// ContentType: 0x16, Version: 0x0303, Length: 2, Body: 0x01, 0x02
	data := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02}

	mock := &mockConn{
		reader: bytes.NewReader(data),
		writer: new(bytes.Buffer),
	}

	contentType, version, body, err := readRecord(mock)
	if err != nil {
		t.Fatalf("readRecord failed: %v", err)
	}

	if contentType != 0x16 {
		t.Errorf("expected content type 0x16, got %x", contentType)
	}
	if version != 0x0303 {
		t.Errorf("expected version 0x0303, got %x%x", version>>8, version&0xFF)
	}
	if !bytes.Equal(body, []byte{0x01, 0x02}) {
		t.Errorf("expected body [0x01, 0x02], got %x", body)
	}
}

func TestWriteRecord(t *testing.T) {
	mock := &mockConn{
		reader: bytes.NewReader([]byte{}),
		writer: new(bytes.Buffer),
	}

	record := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02}
	err := writeRecord(mock, record)
	if err != nil {
		t.Fatalf("writeRecord failed: %v", err)
	}

	if !bytes.Equal(mock.writer.Bytes(), record) {
		t.Errorf("expected written data %x, got %x", record, mock.writer.Bytes())
	}
}

func TestParseAlert(t *testing.T) {
	// Alert record body: [type][description]
	body := []byte{0x02, 0x28} // fatal, handshake_failure

	alertType, description, err := parseAlert(body)
	if err != nil {
		t.Fatalf("parseAlert failed: %v", err)
	}

	if alertType != 0x02 {
		t.Errorf("expected alert type 0x02, got %x", alertType)
	}
	if description != 0x28 {
		t.Errorf("expected description 0x28, got %x", description)
	}

	// Test short body
	_, _, err = parseAlert([]byte{0x02})
	if err == nil {
		t.Error("expected error for short alert body, got nil")
	}
}
