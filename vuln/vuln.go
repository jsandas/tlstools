package vuln

import (
	"github.com/jsandas/tlstools/vuln/ccs"
	"github.com/jsandas/tlstools/vuln/weakkey"
)

// DebianWeakKey detects if key was generated with weak Debian openssl
func DebianWeakKey(keysize int, modulus string) bool {
	return weakkey.WeakKey(keysize, modulus)
}

// Heartbleed used to check for heartbleed on server
func CCSInjection(host string, port string) string {
	return ccs.Check(host, port)
}
