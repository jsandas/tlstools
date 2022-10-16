package ssl

import "github.com/jsandas/etls"

type cipherSuite struct {
	name            string
	MinProtoVersion int
	keyExhange      string
	authentication  string
	encryption      string
	messageAuthCode string
}

var cipherSuites = map[uint16]cipherSuite{
	etls.TLS_AES_256_GCM_SHA384:                            {"TLS_AES_256_GCM_SHA384", etls.VersionTLS13, "any", "any", "AESGCM(256)", "AEAD"},
	etls.TLS_AES_128_GCM_SHA256:                            {"TLS_AES_128_GCM_SHA256", etls.VersionTLS13, "any", "any", "AESGCM(128)", "AEAD"},
	etls.TLS_CHACHA20_POLY1305_SHA256:                      {"TLS_CHACHA20_POLY1305_SHA256", etls.VersionTLS13, "any", "any", "ChaCha20(256)", "AEAD"},
	etls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:     {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", etls.VersionTLS12, "ECDHE", "ECDSA", "ChaCha20(256)", "AEAD"},
	etls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:       {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", etls.VersionTLS12, "ECDHE", "RSA", "ChaCha20(256)", "AEAD"},
	etls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD: {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD", etls.VersionTLS12, "ECDHE", "ECDSA", "ChaCha20(256)", "AEAD"},
	etls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD:   {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", etls.VersionTLS12, "ECDHE", "RSA", "ChaCha20(256)", "AEAD"},
	etls.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD:     {"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", etls.VersionTLS12, "DHE", "RSA", "ChaCha20(256)", "AEAD"},
	etls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:             {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "ECDHE", "RSA", "AESGCM(256)", "AEAD"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:           {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "ECDHE", "ECDSA", "AESGCM(256)", "AEAD"},
	etls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:             {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", etls.VersionTLS12, "ECDHE", "RSA", "AES(256)", "SHA384"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:           {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", etls.VersionTLS12, "ECDHE", "ECDSA", "AES(256)", "SHA384"},
	etls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:                {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "ECDHE", "RSA", "AES(256)", "SHA1"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:              {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "ECDHE", "ECDSA", "AES(256)", "SHA1"},
	etls.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:                {"TLS_DH_DSS_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "DH", "DSS", "AESGCM(256)", "AEAD"},
	etls.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:               {"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "DHE", "DSS", "AESGCM(256)", "AEAD"},
	etls.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:                {"TLS_DH_RSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "DH", "RSA", "AESGCM(256)", "AEAD"},
	etls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:               {"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "DHE", "RSA", "AESGCM(256)", "AEAD"},
	etls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:               {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "DHE", "RSA", "AES(256)", "SHA256"},
	etls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:               {"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "DHE", "DSS", "AES(256)", "SHA256"},
	etls.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:                {"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "DH", "RSA", "AES(256)", "SHA256"},
	etls.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:                {"TLS_DH_DSS_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "DH", "DSS", "AES(256)", "SHA256"},
	etls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:                  {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "AES(256)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:                  {"TLS_DHE_DSS_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "AES(256)", "SHA1"},
	etls.TLS_DH_RSA_WITH_AES_256_CBC_SHA:                   {"TLS_DH_RSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "AES(256)", "SHA1"},
	etls.TLS_DH_DSS_WITH_AES_256_CBC_SHA:                   {"TLS_DH_DSS_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "AES(256)", "SHA1"},
	etls.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:        {"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", etls.VersionTLS12, "ECDHE", "RSA", "Camellia(256)", "SHA384"},
	etls.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:      {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", etls.VersionTLS12, "ECDHE", "ECDSA", "Camellia(256)", "SHA384"},
	etls.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:          {"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "DHE", "RSA", "Camellia(256)", "SHA256"},
	etls.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:          {"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "DHE", "DSS", "Camellia(256)", "SHA256"},
	etls.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:           {"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "DH", "RSA", "Camellia(256)", "SHA256"},
	etls.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:           {"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "DH", "DSS", "Camellia(256)", "SHA256"},
	etls.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:             {"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "Camellia(256)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:             {"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "Camellia(256)", "SHA1"},
	etls.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:              {"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "Camellia(256)", "SHA1"},
	etls.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:              {"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "Camellia(256)", "SHA1"},
	etls.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:                {"TLS_ECDH_anon_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "ECDH", "None", "AES(256)", "SHA1"},
	etls.TLS_DH_anon_WITH_AES_256_GCM_SHA384:               {"TLS_DH_anon_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "DH", "None", "AESGCM(256)", "AEAD"},
	etls.TLS_DH_anon_WITH_AES_256_CBC_SHA256:               {"TLS_DH_anon_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "DH", "None", "AES(256)", "SHA256"},
	etls.TLS_DH_anon_WITH_AES_256_CBC_SHA:                  {"TLS_DH_anon_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "DH", "None", "AES(256)", "SHA1"},
	etls.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:          {"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "DH", "None", "Camellia(256)", "SHA256"},
	etls.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:             {"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "DH", "None", "Camellia(256)", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:              {"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "ECDH", "RSA", "AESGCM(256)", "AEAD"},
	etls.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:            {"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "ECDH", "ECDSA", "AESGCM(256)", "AEAD"},
	etls.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:              {"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", etls.VersionTLS12, "ECDH", "RSA", "AES(256)", "SHA384"},
	etls.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:            {"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", etls.VersionTLS12, "ECDH", "ECDSA", "AES(256)", "SHA384"},
	etls.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:                 {"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "ECDH", "RSA", "AES(256)", "SHA1"},
	etls.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:               {"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "ECDH", "ECDSA", "AES(256)", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:         {"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", etls.VersionTLS12, "ECDH", "RSA", "Camellia(256)", "SHA384"},
	etls.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:       {"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", etls.VersionTLS12, "ECDH", "ECDSA", "Camellia(256)", "SHA384"},
	etls.TLS_RSA_WITH_AES_256_GCM_SHA384:                   {"TLS_RSA_WITH_AES_256_GCM_SHA384", etls.VersionTLS12, "RSA", "RSA", "AESGCM(256)", "AEAD"},
	etls.TLS_RSA_WITH_AES_256_CBC_SHA256:                   {"TLS_RSA_WITH_AES_256_CBC_SHA256", etls.VersionTLS12, "RSA", "RSA", "AES(256)", "SHA256"},
	etls.TLS_RSA_WITH_AES_256_CBC_SHA:                      {"TLS_RSA_WITH_AES_256_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "AES(256)", "SHA1"},
	etls.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:              {"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", etls.VersionTLS12, "RSA", "RSA", "Camellia(256)", "SHA256"},
	etls.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:                 {"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "Camellia(256)", "SHA1"},
	etls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:             {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "ECDHE", "RSA", "AESGCM(128)", "AEAD"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:           {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "ECDHE", "ECDSA", "AESGCM(128)", "AEAD"},
	etls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:             {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "ECDHE", "RSA", "AES(128)", "SHA256"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:           {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "ECDHE", "ECDSA", "AES(128)", "SHA256"},
	etls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:                {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "ECDHE", "RSA", "AES(128)", "SHA1"},
	etls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:              {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "ECDHE", "ECDSA", "AES(128)", "SHA1"},
	etls.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:                {"TLS_DH_DSS_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "DH", "DSS", "AESGCM(128)", "AEAD"},
	etls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:               {"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "DHE", "DSS", "AESGCM(128)", "AEAD"},
	etls.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:                {"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "DH", "RSA", "AESGCM(128)", "AEAD"},
	etls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:               {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "DHE", "RSA", "AESGCM(128)", "AEAD"},
	etls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:               {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "DHE", "RSA", "AES(128)", "SHA256"},
	etls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:               {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "DHE", "DSS", "AES(128)", "SHA256"},
	etls.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:                {"TLS_DH_RSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "DH", "RSA", "AES(128)", "SHA256"},
	etls.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:                {"TLS_DH_DSS_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "DH", "DSS", "AES(128)", "SHA256"},
	etls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:                  {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "AES(128)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:                  {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "AES(128)", "SHA1"},
	etls.TLS_DH_RSA_WITH_AES_128_CBC_SHA:                   {"TLS_DH_RSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "AES(128)", "SHA1"},
	etls.TLS_DH_DSS_WITH_AES_128_CBC_SHA:                   {"TLS_DH_DSS_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "AES(128)", "SHA1"},
	etls.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:        {"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "ECDHE", "RSA", "Camellia(128)", "SHA256"},
	etls.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:      {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "ECDHE", "ECDSA", "Camellia(128)", "SHA256"},
	etls.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:          {"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "DHE", "RSA", "Camellia(128)", "SHA256"},
	etls.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:          {"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "DHE", "DSS", "Camellia(128)", "SHA256"},
	etls.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:           {"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "DH", "RSA", "Camellia(128)", "SHA256"},
	etls.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:           {"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "DH", "DSS", "Camellia(128)", "SHA256"},
	etls.TLS_DHE_RSA_WITH_SEED_CBC_SHA:                     {"TLS_DHE_RSA_WITH_SEED_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "SEED(128)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_SEED_CBC_SHA:                     {"TLS_DHE_DSS_WITH_SEED_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "SEED(128)", "SHA1"},
	etls.TLS_DH_RSA_WITH_SEED_CBC_SHA:                      {"TLS_DH_RSA_WITH_SEED_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "SEED(128)", "SHA1"},
	etls.TLS_DH_DSS_WITH_SEED_CBC_SHA:                      {"TLS_DH_DSS_WITH_SEED_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "SEED(128)", "SHA1"},
	etls.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:             {"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "Camellia(128)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:             {"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "Camellia(128)", "SHA1"},
	etls.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:              {"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "Camellia(128)", "SHA1"},
	etls.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:              {"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "Camellia(128)", "SHA1"},
	etls.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:                {"TLS_ECDH_anon_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "ECDH", "None", "AES(128)", "SHA1"},
	etls.TLS_DH_anon_WITH_AES_128_GCM_SHA256:               {"TLS_DH_anon_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "DH", "None", "AESGCM(128)", "AEAD"},
	etls.TLS_DH_anon_WITH_AES_128_CBC_SHA256:               {"TLS_DH_anon_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "DH", "None", "AES(128)", "SHA256"},
	etls.TLS_DH_anon_WITH_AES_128_CBC_SHA:                  {"TLS_DH_anon_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "DH", "None", "AES(128)", "SHA1"},
	etls.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:          {"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "DH", "None", "Camellia(128)", "SHA256"},
	etls.TLS_DH_anon_WITH_SEED_CBC_SHA:                     {"TLS_DH_anon_WITH_SEED_CBC_SHA", etls.VersionSSL30, "DH", "None", "SEED(128)", "SHA1"},
	etls.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:             {"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "DH", "None", "Camellia(128)", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:              {"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "ECDH", "RSA", "AESGCM(128)", "AEAD"},
	etls.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:            {"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "ECDH", "ECDSA", "AESGCM(128)", "AEAD"},
	etls.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:              {"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "ECDH", "RSA", "AES(128)", "SHA256"},
	etls.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:            {"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "ECDH", "ECDSA", "AES(128)", "SHA256"},
	etls.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:                 {"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "ECDH", "RSA", "AES(128)", "SHA1"},
	etls.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:               {"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "ECDH", "ECDSA", "AES(128)", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:         {"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "ECDH", "RSA", "Camellia(128)", "SHA256"},
	etls.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:       {"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "ECDH", "ECDSA", "Camellia(128)", "SHA256"},
	etls.TLS_RSA_WITH_AES_128_GCM_SHA256:                   {"TLS_RSA_WITH_AES_128_GCM_SHA256", etls.VersionTLS12, "RSA", "RSA", "AESGCM(128)", "AEAD"},
	etls.TLS_RSA_WITH_AES_128_CBC_SHA256:                   {"TLS_RSA_WITH_AES_128_CBC_SHA256", etls.VersionTLS12, "RSA", "RSA", "AES(128)", "SHA256"},
	etls.TLS_RSA_WITH_AES_128_CBC_SHA:                      {"TLS_RSA_WITH_AES_128_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "AES(128)", "SHA1"},
	etls.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:              {"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", etls.VersionTLS12, "RSA", "RSA", "Camellia(128)", "SHA256"},
	etls.TLS_RSA_WITH_SEED_CBC_SHA:                         {"TLS_RSA_WITH_SEED_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "SEED(128)", "SHA1"},
	etls.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:                 {"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "Camellia(128)", "SHA1"},
	etls.TLS_RSA_WITH_IDEA_CBC_SHA:                         {"TLS_RSA_WITH_IDEA_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "IDEA(128)", "SHA1"},
	etls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                    {"TLS_ECDHE_RSA_WITH_RC4_128_SHA", etls.VersionSSL30, "ECDHE", "RSA", "RC4(128)", "SHA1"},
	etls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:                  {"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", etls.VersionSSL30, "ECDHE", "ECDSA", "RC4(128)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_RC4_128_SHA:                      {"TLS_DHE_DSS_WITH_RC4_128_SHA", etls.VersionSSL30, "DHE", "DSS", "RC4(128)", "SHA1"},
	etls.TLS_ECDH_anon_WITH_RC4_128_SHA:                    {"TLS_ECDH_anon_WITH_RC4_128_SHA", etls.VersionSSL30, "ECDH", "None", "RC4(128)", "SHA1"},
	etls.TLS_DH_anon_WITH_RC4_128_MD5:                      {"TLS_DH_anon_WITH_RC4_128_MD5", etls.VersionSSL30, "DH", "None", "RC4(128)", "MD5"},
	etls.TLS_ECDH_RSA_WITH_RC4_128_SHA:                     {"TLS_ECDH_RSA_WITH_RC4_128_SHA", etls.VersionSSL30, "ECDH", "RSA", "RC4(128)", "SHA1"},
	etls.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:                   {"TLS_ECDH_ECDSA_WITH_RC4_128_SHA", etls.VersionSSL30, "ECDH", "ECDSA", "RC4(128)", "SHA1"},
	etls.TLS_RSA_WITH_RC4_128_SHA:                          {"TLS_RSA_WITH_RC4_128_SHA", etls.VersionSSL30, "RSA", "RSA", "RC4(128)", "SHA1"},
	etls.TLS_RSA_WITH_RC4_128_MD5:                          {"TLS_RSA_WITH_RC4_128_MD5", etls.VersionSSL30, "RSA", "RSA", "RC4(128)", "MD5"},
	etls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:               {"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "ECDHE", "RSA", "3DES(168)", "SHA1"},
	etls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:             {"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "ECDHE", "ECDSA", "3DES(168)", "SHA1"},
	etls.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:                 {"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "3DES(168)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:                 {"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "3DES(168)", "SHA1"},
	etls.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:                  {"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "3DES(168)", "SHA1"},
	etls.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:                  {"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "3DES(168)", "SHA1"},
	etls.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:               {"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "ECDH", "None", "3DES(168)", "SHA1"},
	etls.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:                 {"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "DH", "None", "3DES(168)", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:                {"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "ECDH", "RSA", "3DES(168)", "SHA1"},
	etls.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:              {"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "ECDH", "ECDSA", "3DES(168)", "SHA1"},
	etls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                     {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "3DES(168)", "SHA1"},
	etls.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA:           {"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", etls.VersionSSL30, "DHE(1024)", "DSS", "DES(56)", "SHA1"},
	etls.TLS_DHE_RSA_WITH_DES_CBC_SHA:                      {"TLS_DHE_RSA_WITH_DES_CBC_SHA", etls.VersionSSL30, "DHE", "RSA", "DES(56)", "SHA1"},
	etls.TLS_DHE_DSS_WITH_DES_CBC_SHA:                      {"TLS_DHE_DSS_WITH_DES_CBC_SHA", etls.VersionSSL30, "DHE", "DSS", "DES(56)", "SHA1"},
	etls.TLS_DH_RSA_WITH_DES_CBC_SHA:                       {"TLS_DH_RSA_WITH_DES_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "DES(56)", "SHA1"},
	etls.TLS_DH_DSS_WITH_DES_CBC_SHA:                       {"TLS_DH_DSS_WITH_DES_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "DES(56)", "SHA1"},
	etls.TLS_DH_anon_WITH_DES_CBC_SHA:                      {"TLS_DH_anon_WITH_DES_CBC_SHA", etls.VersionSSL30, "DH", "None", "DES(56)", "SHA1"},
	etls.TLS_RSA_WITH_DES_CBC_SHA:                          {"TLS_RSA_WITH_DES_CBC_SHA", etls.VersionSSL30, "RSA", "RSA", "DES(56)", "SHA1"},
	etls.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA:               {"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", etls.VersionSSL30, "RSA(1024)", "RSA", "DES(56)", "SHA1"},
	etls.TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5:            {"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", etls.VersionSSL30, "RSA(1024)", "RSA", "RC2(56)", "MD5 "},
	etls.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA:            {"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", etls.VersionSSL30, "DHE(1024)", "DSS", "RC4(56)", "SHA1"},
	etls.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA:                {"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", etls.VersionSSL30, "RSA(1024)", "RSA", "RC4(56)", "SHA1"},
	etls.TLS_RSA_EXPORT1024_WITH_RC4_56_MD5:                {"TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", etls.VersionSSL30, "RSA(1024)", "RSA", "RC4(56)", "MD5 "},
	etls.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:             {"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "DHE(512)", "RSA", "DES(40)", "SHA1"},
	etls.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:             {"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "DHE(512)", "DSS", "DES(40)", "SHA1"},
	etls.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:              {"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "DH", "RSA", "DES(40)", "SHA1"},
	etls.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:              {"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "DH", "DSS", "DES(40)", "SHA1"},
	etls.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:             {"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "DH(512)", "None", "DES(40)", "SHA1"},
	etls.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:                 {"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", etls.VersionSSL30, "RSA(512)", "RSA", "DES(40)", "SHA1"},
	etls.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:                {"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", etls.VersionSSL30, "RSA(512)", "RSA", "RC2(40)", "MD5 "},
	etls.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:                {"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", etls.VersionSSL30, "DH(512)", "None", "RC4(40)", "MD5 "},
	etls.TLS_RSA_EXPORT_WITH_RC4_40_MD5:                    {"TLS_RSA_EXPORT_WITH_RC4_40_MD5", etls.VersionSSL30, "RSA(512)", "RSA", "RC4(40)", "MD5 "},
	etls.TLS_ECDHE_RSA_WITH_NULL_SHA:                       {"TLS_ECDHE_RSA_WITH_NULL_SHA", etls.VersionSSL30, "ECDHE", "RSA", "None", "SHA1"},
	etls.TLS_ECDHE_ECDSA_WITH_NULL_SHA:                     {"TLS_ECDHE_ECDSA_WITH_NULL_SHA", etls.VersionSSL30, "ECDHE", "ECDSA", "None", "SHA1"},
	etls.TLS_ECDH_anon_WITH_NULL_SHA:                       {"TLS_ECDH_anon_WITH_NULL_SHA", etls.VersionSSL30, "ECDH", "None", "None", "SHA1"},
	etls.TLS_ECDH_RSA_WITH_NULL_SHA:                        {"TLS_ECDH_RSA_WITH_NULL_SHA", etls.VersionSSL30, "ECDH", "RSA", "None", "SHA1"},
	etls.TLS_ECDH_ECDSA_WITH_NULL_SHA:                      {"TLS_ECDH_ECDSA_WITH_NULL_SHA", etls.VersionSSL30, "ECDH", "ECDSA", "None", "SHA1"},
	etls.TLS_RSA_WITH_NULL_SHA256:                          {"TLS_RSA_WITH_NULL_SHA256", etls.VersionTLS12, "RSA", "RSA", "None", "SHA256"},
	etls.TLS_RSA_WITH_NULL_SHA:                             {"TLS_RSA_WITH_NULL_SHA", etls.VersionSSL30, "RSA", "RSA", "None", "SHA1"},
	etls.TLS_RSA_WITH_NULL_MD5:                             {"TLS_RSA_WITH_NULL_MD5", etls.VersionSSL30, "RSA", "RSA", "None", "MD5"},
}