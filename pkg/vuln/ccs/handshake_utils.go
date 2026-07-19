package ccs

import (
	"fmt"
	"io"
	"net"
)

// ProbeStatus represents the outcome of a version probe.
type ProbeStatus string

const (
	ProbeStatusSuccess       ProbeStatus = "SUCCESS"
	ProbeStatusFailed        ProbeStatus = "FAILED"
	ProbeStatusNotVulnerable ProbeStatus = "NOT_VULNERABLE"
	ProbeStatusError         ProbeStatus = "ERROR"
)

// makeClientHello generates a raw TLS record containing a ClientHello.
func makeClientHello(version uint16) []byte {
	// In a real probe, we might use random bytes. For tests, we can be deterministic.
	// However, the structure remains the same.

	var body []byte
	body = append(body, 0x01) // type: client_hello

	// Placeholder for handshake length (3 bytes)
	body = append(body, 0x00, 0x00, 0x00)

	// Version (2 bytes)
	body = append(body, byte(version>>8), byte(version&0xFF))

	// Random (32 bytes)
	random := make([]byte, 32) // All zeros for determinism in tests
	body = append(body, random...)

	// Session ID length (1 byte)
	body = append(body, 0x00)

	// Cipher Suites
	body = append(body, 0x00, 0x02) // length: 2 bytes
	body = append(body, 0x00, 0x35) // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0x00, 0x2f) // TLS_RSA_WITH_AES_256_CBC_SHA

	// Compression Methods (1 byte length, 0x01 NULL)
	body = append(body, 0x01, 0x00)

	// Update the length in the handshake header
	handshakeLength := len(body) - 4
	body[1] = byte(handshakeLength >> 16)
	body[2] = byte(handshakeLength >> 8)
	body[3] = byte(handshakeLength & 0xFF)

	// Create the final TLS Record: [ContentType][Version][Length][Body]
	record := []byte{0x16, byte(version >> 8), byte(version & 0xFF)}
	record = append(record, body...)

	return record
}

// makeCCS generates a raw TLS record containing a ChangeCipherSpec.
func makeCCS(version uint16) []byte {
	return []byte{0x14, byte(version >> 8), byte(version & 0xFF), 0x00, 0x00}
}

// readRecord reads a single TLS record from the connection.
func readRecord(conn net.Conn) (contentType byte, version uint16, body []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, 0, nil, err
	}

	contentType = header[0]
	version = uint16(header[1])<<8 | uint16(header[2])
	length := uint16(header[3])<<8 | uint16(header[4])

	body = make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, 0, nil, err
	}

	return contentType, version, body, nil
}

// parseAlert extracts the alert type and description from a record body.
func parseAlert(body []byte) (alertType byte, description byte, err error) {
	if len(body) < 2 {
		return 0, 0, fmt.Errorf("alert body too short")
	}
	return body[0], body[1], nil
}

// writeRecord writes a raw TLS record to the connection.
func writeRecord(conn net.Conn, record []byte) error {
	if len(record) < 5 {
		return fmt.Errorf("record too short to be a valid TLS record")
	}
	_, err := conn.Write(record)
	return err
}

// probeVersion performs a version-specific CCS vulnerability probe.
func probeVersion(conn net.Conn, version uint16) (vulnerable bool, status ProbeStatus, err error) {
	// 1. Send ClientHello
	clientHello := makeClientHello(version)
	if err := writeRecord(conn, clientHello); err != nil {
		return false, ProbeStatusError, err
	}

	// 2. Read first response (ServerHello / Certificate / etc.)
	contentType, _, _, err := readRecord(conn)
	if err != nil {
		return false, ProbeStatusError, err
	}

	// If the server sends an alert immediately after ClientHello
	if contentType == 0x15 { // Alert
		return false, ProbeStatusNotVulnerable, nil
	}

	// 3. Send first CCS
	ccs1 := makeCCS(version)
	if err := writeRecord(conn, ccs1); err != nil {
		return false, ProbeStatusError, err
	}

	// 4. Send second CCS
	ccs2 := makeCCS(version)
	if err := writeRecord(conn, ccs2); err != nil {
		return false, ProbeStatusError, err
	}

	// 5. Evaluate outcome
	// We attempt to read one more record to see how the server reacts to the CCS sequence.
	contentType, _, _, err = readRecord(conn)
	if err != nil {
		if err == io.EOF {
			return true, ProbeStatusSuccess, nil
		}
		return false, ProbeStatusError, err
	}

	if contentType == 0x15 { // Alert
		return false, ProbeStatusNotVulnerable, nil
	}

	// If we receive a non-alert record, it's likely the server is accepting the handshake.
	return true, ProbeStatusSuccess, nil
}
