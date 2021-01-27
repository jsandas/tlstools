package ssl

import (
	"crypto/tls"
	"sort"
	"strings"
	"sync"

	"github.com/jsandas/tlstools/logger"
)

// Check performs tls handshakes to find support
// ciphers and protocols
func Check(host string, port string, keyType string) map[string][]string {
	var WG sync.WaitGroup
	var mutex = &sync.Mutex{}
	supportedConfig := make(map[string][]string)
	var protoList []int
	var cipherList []string

	protoList = getProtocols(host, port)

	for i := range protoList {
		WG.Add(1)
		go func(p int) {
			pname := protocolVersionMap[protoList[p]]

			cipherList = getCiphers(host, port, protoList[p], keyType)

			if len(cipherList) > 0 {
				mutex.Lock()
				supportedConfig[pname.name] = cipherList
				mutex.Unlock()
			}

			WG.Done()
		}(i)
	}
	WG.Wait()

	// Check sslv2 support
	sslv2 := sslv2Check(host, port)
	if val, ok := sslv2["SSLv2"]; ok {
		supportedConfig["SSLv2"] = val
	}

	logger.Debugf("supported configurations: %v", supportedConfig)
	return supportedConfig
}

func connect(host string, port string, p int, c int) bool {
	var cipher uint16 = cipherSuitesMap[c].cipher

	if p == 768 || useOpenSSL(c) {
		return opensslDial(host, port, p, []uint16{cipher})
	}

	return serverDial(host, port, p, []uint16{cipher})
}

// getProtocols returns list of support TLS protocols
func getProtocols(host string, port string) []int {
	var protoList []int

	for p := range protocolVersionMap {
		var supported bool
		if p == 768 {
			supported = opensslDial(host, port, p, nil)
		} else {
			supported = serverDial(host, port, p, nil)
		}

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
	var tmpCipherList []int
	var cWG sync.WaitGroup
	var cmtex = &sync.Mutex{}

	cipherChan := make(chan int)
	for i := range cipherSuitesMap {
		cWG.Add(1)
		go func(i int) {
			var supported bool

			if !proceed(i, protocol, keyType) {
				cWG.Done()
				return
			}

			supported = connect(host, port, protocol, i)

			if supported {
				cipherChan <- i
			}
			cWG.Done()
		}(i)

		go func() {
			for i := range cipherChan {
				cmtex.Lock()
				tmpCipherList = append(tmpCipherList, i)
				cmtex.Unlock()
			}
		}()
		cWG.Wait()
	}

	sort.Ints(tmpCipherList)
	for i := range tmpCipherList {
		cInt := tmpCipherList[i]
		cipherList = append(cipherList, cipherSuitesMap[cInt].name)
	}
	logger.Debugf("supported ciphers %s: %v", protocolVersionMap[protocol].name, cipherList)

	return cipherList
}

// proceed determines if check should proceed
func proceed(c int, p int, k string) bool {
	var b bool

	// Only test ciphers matching keyType (RSA vs ECC)
	if !strings.Contains(cipherSuitesMap[c].name, k) && !(strings.HasPrefix(cipherSuitesMap[c].name, "TLS_AES") || strings.HasPrefix(cipherSuitesMap[c].name, "TLS_CHACHA20")) {
		return b
	}
	// Only test GCM ciphers with TLS1.2/1.3
	if p < tls.VersionTLS12 && (strings.Contains(cipherSuitesMap[c].name, "GCM") || strings.Contains(cipherSuitesMap[c].name, "CHACHA")) {
		return b
	}
	// Don't try tls1.3 ciphers when protocol is < tls1.3
	if p < tls.VersionTLS13 && (strings.HasPrefix(cipherSuitesMap[c].name, "TLS_AES") || strings.HasPrefix(cipherSuitesMap[c].name, "TLS_CHACHA20")) {
		return b
	}
	// Only test tls1.3 ciphers with tls1.3
	if p == tls.VersionTLS13 && !(strings.HasPrefix(cipherSuitesMap[c].name, "TLS_AES") || strings.HasPrefix(cipherSuitesMap[c].name, "TLS_CHACHA20")) {
		return b
	}

	return true
}

func useOpenSSL(c int) bool {
	var b bool
	var strList = []string{"MD5", "TLS_DHE", "CAMELLIA256", "EXPORT"}
	var cs = cipherSuitesMap[c].name
	for _, s := range strList {
		if strings.Contains(cs, s) {
			return true
		}
	}

	return b
}
