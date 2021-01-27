package ssl

// func TestStartTLS(t *testing.T) {
// 	var first = []byte("220 test.test.test server\r\n")
// 	var second = []byte("220 2.0.0 Ready to start TLS\r\n")

// 	server, client := net.Pipe()

// 	go func() {
// 		server.Write(first)
// 		// b, err := ioutil.ReadAll(server)
// 		// t.Errorf("got: %v %v", err, b)
// 	}()

// 	go func() {
// 		server.Write(second)
// 		time.Sleep(3 * time.Second)
// 		server.Close()
// 	}()

// 	r := bufio.NewReader(client)
// 	w := bufio.NewWriter(client)

// 	var err error

// 	err = run(w, r, "smtp")

// 	if err != nil {
// 		t.Errorf("Got an error, got: %v", err)
// 	}
// }
