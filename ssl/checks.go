package ssl

import (
	logger "github.com/jsandas/gologger"
)

// Check performs tls handshakes to find support
// ciphers and protocols
func Check(host string, port string, keyType string) map[string][]string {
	// var WG sync.WaitGroup
	// var mutex = &sync.Mutex{}
	supportedConfig := make(map[string][]string)
	var protoList []int
	var cipherList []string

	protoList = getProtocols(host, port)

	for i := range protoList {
		// WG.Add(1)
		// go func(p int) {
		pname := protocolVersionMap[protoList[i]]

		cipherList = getCiphers(host, port, protoList[i], keyType)

		if len(cipherList) > 0 {
			// mutex.Lock()
			supportedConfig[pname.name] = cipherList
			// mutex.Unlock()
		}

		// 	WG.Done()
		// }(i)
	}
	// WG.Wait()

	// Check sslv2 support
	sslv2 := sslv2Check(host, port)
	if val, ok := sslv2["SSLv2"]; ok {
		supportedConfig["SSLv2"] = val
	}

	logger.Debugf("supported configurations: %v", supportedConfig)
	return supportedConfig
}

func connect(host string, port string, p int, c uint16) bool {
	var cipher uint16 = c

	return serverDial(host, port, p, []uint16{cipher})
}

// getProtocols returns list of support TLS protocols
func getProtocols(host string, port string) []int {
	var protoList []int

	for p := range protocolVersionMap {

		supported := serverDial(host, port, p, nil)

		if supported {
			protoList = append(protoList, p)
		}
	}

	logger.Debugf("supported protocols: %v", protoList)
	return protoList
}

// getCiphers returns list of support TLS ciphers
func getCiphers(host string, port string, protocol int, keyType string) []string {
	var cipherList []string
	// var tmpCipherList []uint16
	// var cWG sync.WaitGroup
	// var cmtex = &sync.Mutex{}

	// cipherChan := make(chan string)
	for i, c := range cipherSuites {
		// cWG.Add(1)
		// go func(c cipherSuite) {
		var supported bool

		if !proceed(c, protocol, keyType) {
			// cWG.Done()
			// return
			continue
		}
		logger.Debugf("testing cipher: %s | protocol: %d", c.name, protocol)
		supported = connect(host, port, protocol, i)

		if supported {
			cipherList = append(cipherList, c.name)
			// cipherChan <- c.name
		}
		// 	cWG.Done()
		// }(c)

		// go func() {
		// 	for s := range cipherChan {
		// 		cmtex.Lock()
		// 		cipherList = append(cipherList, s)
		// 		cmtex.Unlock()
		// 	}
		// }()
		// cWG.Wait()
	}

	// sort.Ints(tmpCipherList)
	// for i := range tmpCipherList {
	// 	cInt := tmpCipherList[i]
	// 	cipherList = append(cipherList, cipherSuitesMap[cInt].name)
	// }
	logger.Debugf("supported ciphers %s: %v", protocolVersionMap[protocol].name, cipherList)

	return cipherList
}

// proceed determines if check should proceed
func proceed(c cipherSuite, p int, k string) bool {
	// Only test ciphers matching keyType (RSA vs ECC)
	if (c.authentication != k) && (c.authentication != "None") && (c.authentication != "any") {
		// logger.Debugf("skip cipher %s | %d reason: wrong_keytype", c.name, p)
		return false
	}

	// skip cipher if protocol too low
	if p < c.MinProtoVersion {
		// logger.Debugf("skip cipher %s | %d reason: under_min_version", c.name, p)
		return false
	}

	// skip cipher if cipher is not for tlsv1.3
	if (p == VersionTLS13) && (c.MinProtoVersion != p) {
		// logger.Debugf("skip cipher %s | %d reason: not_tls13_cipher", c.name, p)
		return false
	}

	return true
}
