package ssl

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

type protocolInfo struct {
	name        string
	opensslname string
}

var protocolVersionMap = map[int]protocolInfo{
	VersionTLS13: {"TLSv1.3", "-tls1_3"},
	VersionTLS12: {"TLSv1.2", "-tls1_2"},
	VersionTLS11: {"TLSv1.1", "-tls1_1"},
	VersionTLS10: {"TLSv1.0", "-tls1"},
	VersionSSL30: {"SSLv3", "-ssl3"},
}
