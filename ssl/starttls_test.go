package ssl

import (
	"fmt"
	"log"
	"net"
	"testing"
)

// func TestStartTLSMTP(t *testing.T) {
// 	var first = []byte("220 test.test.test server\r\n")
// 	var second = []byte("250-STARTTLS")
// 	var third = []byte("220 2.0.0 Ready to start TLS\r\n")

// 	// Start the new server.
// 	srv, err := net.Listen("tcp", ":25")
// 	if err != nil {
// 		log.Println("error starting TCP server")
// 		return
// 	}

// 	var srvConn net.Conn

// 	go func() {
// 		srvConn, err = srv.Accept()
// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}

// 		srvConn.Write(first)
// 		srvConn.Write(second)
// 		srvConn.Write(third)
// 	}()

// 	client, err := net.Dial("tcp", srv.Addr().String())
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	err = StartTLS(client, "25")

// 	if err != nil {
// 		t.Errorf("Got an error, got: %v", err)
// 	}
// }

func TestStartTLSFTP(t *testing.T) {
	var first = []byte("220 test.test.test server\r\n")
	var second = []byte("234 2.0.0 Ready to start TLS\r\n")

	// Start the new server.
	srv, err := net.Listen("tcp", ":21")
	if err != nil {
		log.Println("error starting TCP server")
		return
	}

	var srvConn net.Conn

	go func() {
		srvConn, err = srv.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		srvConn.Write(first)
		srvConn.Write(second)
	}()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		fmt.Println(err)
		return
	}

	err = StartTLS(client, "21")

	if err != nil {
		t.Errorf("Got an error, got: %v", err)
	}
}
