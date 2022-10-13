package ssl

import "github.com/jsandas/etls"

var protocolVersionMap = map[int]string{
	etls.VersionTLS13: "TLSv1.3",
	etls.VersionTLS12: "TLSv1.2",
	etls.VersionTLS11: "TLSv1.1",
	etls.VersionTLS10: "TLSv1.0",
	etls.VersionSSL30: "SSLv3",
}
