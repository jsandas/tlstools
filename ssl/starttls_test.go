package ssl

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"
)

type testServerData struct {
	greetMSG string
	authMSG  string
	respMSG  string
}

// testServer is used to simulate responses from a server
// for testing StartTLS functionality
func testServer(port string, msg testServerData) error {
	// Start the new server.
	srv, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Println("error starting TCP server")
		return err
	}

	var srvConn net.Conn

	go func() {
		srvConn, err = srv.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		srvConn.Write([]byte(msg.greetMSG))
		time.Sleep(1 * time.Second)

		// need to find a way to check client auth message that doesn't hang
		time.Sleep(1 * time.Second)
		// rgx := regexp.MustCompile(msg.authMSG)
		// for {
		// 	var b []byte
		// 	srvConn.Read(b)
		// 	if rgx.MatchString(string(b)) {
		// 		break
		// 	}
		// }

		srvConn.Write([]byte(msg.respMSG))
	}()

	client, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = StartTLS(client, port)

	return err
}

func TestStartTLSMTP(t *testing.T) {
	// test server data
	msg := testServerData{
		greetMSG: "220 test.test.test server\r\n250-STARTTLS\r\n",
		authMSG:  "STARTTLS\r\n",
		respMSG:  "220 ready\r\n",
	}

	err := testServer("25", msg)

	if err != nil {
		t.Errorf("Got an error, got: %v", err)
	}
}

func TestStartTLSFTP(t *testing.T) {
	// test server data
	msg := testServerData{
		greetMSG: "220 test.test.test server\r\n",
		authMSG:  "AUTH TLS\r\n",
		respMSG:  "234 ready\r\n",
	}

	err := testServer("21", msg)

	if err != nil {
		t.Errorf("Got an error, got: %v", err)
	}
}

func TestStartTLSPOP3(t *testing.T) {
	// test server data
	msg := testServerData{
		greetMSG: "+OK test data\r\n",
		authMSG:  "STLS\r\n",
		respMSG:  "+OK \r\n",
	}

	err := testServer("110", msg)

	if err != nil {
		t.Errorf("Got an error, got: %v", err)
	}
}
