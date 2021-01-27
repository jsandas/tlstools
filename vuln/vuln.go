package vuln

import (
	"github.com/jsandas/tlstools/vuln/heartbleed"
	"github.com/jsandas/tlstools/vuln/weakkey"
)

// DebianWeakKey detects if key was generated with weak Debian openssl
func DebianWeakKey(keysize int, modulus string) bool {
	return weakkey.WeakKey(keysize, modulus)
}

// Heartbleed used to check for heartbleed on server
// using github.com/FiloSottile/Heartbleed for this check
func Heartbleed(host string, port string, tlsVers int) string {
	return heartbleed.Heartbleed(host, port, tlsVers)
}
