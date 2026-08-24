package minitls

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// TLS version constants (following Go's crypto/tls conventions)
const (
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// CertificateFetcher is an interface for fetching certificates from URLs.
// Implementations can use HTTP or any other transport mechanism.
//
// For production use, wrap your fetcher with CachedCertificateFetcher to enable
// automatic caching with 1 week TTL and LRU eviction:
//
//	baseFetcher := &MyHTTPFetcher{}
//	cachedFetcher, err := NewCachedCertificateFetcher(baseFetcher, logger)
//	if err != nil {
//	    return err
//	}
//	defer cachedFetcher.Shutdown(context.Background())
//
//	config := &Config{
//	    CertFetcher: cachedFetcher,
//	}
type CertificateFetcher interface {
	// FetchCertificate downloads a certificate from the given URL.
	// Returns DER-encoded certificate bytes.
	FetchCertificate(url string) ([]byte, error)
}

// Config contains configuration for TLS clients and servers.
// Following Go's crypto/tls.Config design patterns.
type Config struct {
	// MinVersion contains minimum TLS version that is acceptable.
	// If zero, TLS 1.2 is currently taken as the minimum.
	MinVersion uint16

	// MaxVersion contains maximum TLS version that is acceptable.
	// If zero, TLS 1.3 is currently taken as the maximum.
	MaxVersion uint16

	// CipherSuites is a list of enabled TLS cipher suites.
	// If nil, a default safe list is used.
	CipherSuites []uint16

	// EnableTLS12CBC appends the TLS 1.2 CBC compatibility suites to the
	// default list. It defaults to false so callers that predate CBC support
	// retain the original AEAD-only negotiation surface.
	EnableTLS12CBC bool

	// ServerName is the hostname used to verify the server certificate.
	// For clients only.
	ServerName string

	// NextProtos is a list of supported application level protocols,
	// in order of preference. (ALPN)
	NextProtos []string

	// CertFetcher is used to download missing intermediate certificates via AIA.
	// If nil, automatic certificate fetching is disabled.
	CertFetcher CertificateFetcher
}

// supportedVersions returns the list of supported TLS versions for this config
// Versions are returned in preference order (highest/newest first) per RFC 8446
func (c *Config) supportedVersions() []uint16 {
	minVer := c.MinVersion
	if minVer == 0 {
		minVer = VersionTLS12 // Default minimum
	}

	maxVer := c.MaxVersion
	if maxVer == 0 {
		maxVer = VersionTLS13 // Default maximum
	}

	var versions []uint16
	// Iterate in descending order: prefer newer versions (TLS 1.3 before TLS 1.2)
	for ver := maxVer; ver >= minVer; ver-- {
		if ver == VersionTLS12 || ver == VersionTLS13 {
			versions = append(versions, ver)
		}
	}
	return versions
}

// maxSupportedVersion returns the maximum supported version for this config
func (c *Config) maxSupportedVersion() uint16 {
	versions := c.supportedVersions()
	if len(versions) == 0 {
		return VersionTLS13 // Default
	}
	// versions[0] is the highest since supportedVersions() returns in descending order
	return versions[0]
}

// defaultCipherSuites returns the default cipher suites for a given TLS version
// ChaCha20-Poly1305 is preferred as client runs on mobile (no hardware AES)
func defaultCipherSuites(version uint16) []uint16 {
	switch version {
	case VersionTLS13:
		return []uint16{
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
		}
	case VersionTLS12:
		suites := []uint16{
			// ECDSA ciphers first (smaller keys, faster on mobile)
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			// RSA ciphers
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
		return suites
	default:
		return nil
	}
}

// tls12CBCCipherSuites returns the complete AES-CBC compatibility set in
// preference order. AEAD suites are always advertised before this list.
func tls12CBCCipherSuites() []uint16 {
	return []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA256,
	}
}

// cipherSuites returns the cipher suites to use for this config
func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}

	// When advertising multiple TLS versions, we need to include cipher suites for all versions
	// Otherwise the server cannot negotiate the lower version
	versions := c.supportedVersions()
	var suites []uint16

	// Add cipher suites for each supported version (in order of preference)
	// Note: TLS 1.2 and TLS 1.3 cipher suites are disjoint, so no deduplication needed
	for _, ver := range versions {
		suites = append(suites, defaultCipherSuites(ver)...)
		if ver == VersionTLS12 && c.EnableTLS12CBC {
			suites = append(suites, tls12CBCCipherSuites()...)
		}
	}

	return suites
}

// TLS 1.3 Record Layer
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

// TLS 1.2 AES-CBC cipher suites supported by the trusted-TEE compatibility
// path. TLS 1.0 and TLS 1.1 are not supported.
const (
	TLS_RSA_WITH_AES_128_CBC_SHA            = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256         = 0x003c
	TLS_RSA_WITH_AES_256_CBC_SHA256         = 0x003d
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    = 0xc00a
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = 0xc027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = 0xc028
)

type TLS12KeyExchange uint8

const (
	TLS12KeyExchangeUnknown TLS12KeyExchange = iota
	TLS12KeyExchangeECDHE
	TLS12KeyExchangeRSA
)

type TLS12Authentication uint8

const (
	TLS12AuthenticationUnknown TLS12Authentication = iota
	TLS12AuthenticationRSA
	TLS12AuthenticationECDSA
)

type HandshakeType uint8

// TLS Handshake Message Types (shared between TLS 1.2 and 1.3)
const (
	typeClientHello      HandshakeType = 1
	typeServerHello      HandshakeType = 2
	typeNewSessionTicket HandshakeType = 4
	// TLS 1.2 specific messages
	typeCertificateRequest HandshakeType = 13
	typeServerKeyExchange  HandshakeType = 12
	typeClientKeyExchange  HandshakeType = 16
	typeServerHelloDone    HandshakeType = 14
	// TLS 1.3 specific messages
	typeEncryptedExtensions HandshakeType = 8
	// Shared messages
	typeCertificate       HandshakeType = 11
	typeCertificateVerify HandshakeType = 15
	typeFinished          HandshakeType = 20
)

// TLS 1.3 Cipher Suites
const (
	TLS_AES_128_GCM_SHA256       = 0x1301
	TLS_AES_256_GCM_SHA384       = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303
)

// TLS 1.2 AEAD Cipher Suites (following Go's crypto/tls constants)
const (
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
)

// CipherSuiteInfo provides information about a cipher suite
type CipherSuiteInfo struct {
	ID             uint16
	Name           string
	KeySize        int    // Key size in bytes
	BlockSize      int    // Block size in bytes (16 for AES, 64 for ChaCha20)
	IVSize         int    // IV/Nonce size in bytes
	TagSize        int    // Auth tag size in bytes
	HashFunc       string // Hash function name
	IsTLS13        bool
	IsCBC          bool
	MACSize        int
	MACHash        string
	KeyExchange    TLS12KeyExchange
	Authentication TLS12Authentication
}

// GetCipherSuiteInfo returns information about a cipher suite
func GetCipherSuiteInfo(cipherSuite uint16) *CipherSuiteInfo {
	switch cipherSuite {
	// TLS 1.3 cipher suites
	case TLS_AES_128_GCM_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_AES_128_GCM_SHA256, Name: "TLS_AES_128_GCM_SHA256",
			KeySize: 16, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: true,
		}
	case TLS_AES_256_GCM_SHA384:
		return &CipherSuiteInfo{
			ID: TLS_AES_256_GCM_SHA384, Name: "TLS_AES_256_GCM_SHA384",
			KeySize: 32, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA384", IsTLS13: true,
		}
	case TLS_CHACHA20_POLY1305_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_CHACHA20_POLY1305_SHA256, Name: "TLS_CHACHA20_POLY1305_SHA256",
			KeySize: 32, BlockSize: 64, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: true,
		}
	// TLS 1.2 cipher suites
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			KeySize: 16, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationRSA,
		}
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			KeySize: 16, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationECDSA,
		}
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			KeySize: 32, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA384", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationRSA,
		}
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			KeySize: 32, BlockSize: 16, IVSize: 12, TagSize: 16,
			HashFunc: "SHA384", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationECDSA,
		}
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			KeySize: 32, BlockSize: 64, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationRSA,
		}
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return &CipherSuiteInfo{
			ID: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			KeySize: 32, BlockSize: 64, IVSize: 12, TagSize: 16,
			HashFunc: "SHA256", IsTLS13: false, KeyExchange: TLS12KeyExchangeECDHE, Authentication: TLS12AuthenticationECDSA,
		}
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 16, 20, "SHA1", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA)
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 16, 20, "SHA1", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA)
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 32, 20, "SHA1", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA)
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 32, 20, "SHA1", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA)
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 16, 32, "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA)
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 16, 32, "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA)
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 32, 48, "SHA384", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA)
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 32, 48, "SHA384", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA)
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_RSA_WITH_AES_128_CBC_SHA", 16, 20, "SHA1", TLS12KeyExchangeRSA, TLS12AuthenticationRSA)
	case TLS_RSA_WITH_AES_256_CBC_SHA:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_RSA_WITH_AES_256_CBC_SHA", 32, 20, "SHA1", TLS12KeyExchangeRSA, TLS12AuthenticationRSA)
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_RSA_WITH_AES_128_CBC_SHA256", 16, 32, "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA)
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return tls12CBCSuiteInfo(cipherSuite, "TLS_RSA_WITH_AES_256_CBC_SHA256", 32, 32, "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA)
	default:
		return nil
	}
}

func tls12CBCSuiteInfo(id uint16, name string, keySize, macSize int, macHash string, keyExchange TLS12KeyExchange, authentication TLS12Authentication) *CipherSuiteInfo {
	prfHash := "SHA256"
	if macHash == "SHA384" {
		prfHash = "SHA384"
	}
	return &CipherSuiteInfo{
		ID: id, Name: name, KeySize: keySize, BlockSize: 16, IVSize: 16,
		TagSize: macSize, HashFunc: prfHash, IsTLS13: false, IsCBC: true,
		MACSize: macSize, MACHash: macHash, KeyExchange: keyExchange, Authentication: authentication,
	}
}

// IsChaCha20 returns true if the cipher suite uses ChaCha20
func IsChaCha20(cipherSuite uint16) bool {
	info := GetCipherSuiteInfo(cipherSuite)
	return info != nil && info.BlockSize == 64
}

// IsAESGCM returns true if the cipher suite uses AES-GCM
func IsAESGCM(cipherSuite uint16) bool {
	info := GetCipherSuiteInfo(cipherSuite)
	return info != nil && !info.IsCBC && info.BlockSize == 16
}

func IsTLS12CBCCipherSuite(cipherSuite uint16) bool {
	info := GetCipherSuiteInfo(cipherSuite)
	return info != nil && !info.IsTLS13 && info.IsCBC
}

func TLS12CipherSuiteKeyExchange(cipherSuite uint16) TLS12KeyExchange {
	info := GetCipherSuiteInfo(cipherSuite)
	if info == nil || info.IsTLS13 {
		return TLS12KeyExchangeUnknown
	}
	if info.KeyExchange != TLS12KeyExchangeUnknown {
		return info.KeyExchange
	}
	return TLS12KeyExchangeECDHE
}

func TLS12CipherSuiteAuthentication(cipherSuite uint16) TLS12Authentication {
	info := GetCipherSuiteInfo(cipherSuite)
	if info == nil || info.IsTLS13 {
		return TLS12AuthenticationUnknown
	}
	return info.Authentication
}

// ParseCipherSuite converts a cipher suite string (hex or name) to uint16 ID
func ParseCipherSuite(cipherSuite string) (uint16, error) {
	if cipherSuite == "" {
		return 0, fmt.Errorf("empty cipher suite")
	}

	// Try parsing as hex first (e.g., "0x1301" or "1301"). A well-formed hex
	// value still has to name a suite we actually implement.
	cipherSuite = strings.TrimSpace(cipherSuite)
	if strings.HasPrefix(strings.ToLower(cipherSuite), "0x") {
		if val, err := strconv.ParseUint(cipherSuite[2:], 16, 16); err == nil {
			if GetCipherSuiteInfo(uint16(val)) == nil {
				return 0, fmt.Errorf("unknown cipher suite '%s'", cipherSuite)
			}
			return uint16(val), nil
		}
	} else if val, err := strconv.ParseUint(cipherSuite, 16, 16); err == nil {
		if GetCipherSuiteInfo(uint16(val)) == nil {
			return 0, fmt.Errorf("unknown cipher suite '%s'", cipherSuite)
		}
		return uint16(val), nil
	}

	// Try matching by name
	upperName := strings.ToUpper(cipherSuite)
	switch upperName {
	// TLS 1.3
	case "TLS_AES_128_GCM_SHA256":
		return TLS_AES_128_GCM_SHA256, nil
	case "TLS_AES_256_GCM_SHA384":
		return TLS_AES_256_GCM_SHA384, nil
	case "TLS_CHACHA20_POLY1305_SHA256":
		return TLS_CHACHA20_POLY1305_SHA256, nil
	// TLS 1.2
	case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		return TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		return TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		return TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		return TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
		return TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
		return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
		return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
		return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
		return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":
		return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":
		return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, nil
	case "TLS_RSA_WITH_AES_128_CBC_SHA":
		return TLS_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_256_CBC_SHA":
		return TLS_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_128_CBC_SHA256":
		return TLS_RSA_WITH_AES_128_CBC_SHA256, nil
	case "TLS_RSA_WITH_AES_256_CBC_SHA256":
		return TLS_RSA_WITH_AES_256_CBC_SHA256, nil
	}

	return 0, fmt.Errorf("unknown cipher suite '%s'", cipherSuite)
}

// IsValidCipherSuite checks if a cipher suite string is valid
func IsValidCipherSuite(cipherSuite string) bool {
	_, err := ParseCipherSuite(cipherSuite)
	return err == nil
}

// IsTLS12CipherSuite checks if a cipher suite belongs to TLS 1.2
func IsTLS12CipherSuite(cipherSuite uint16) bool {
	info := GetCipherSuiteInfo(cipherSuite)
	return info != nil && !info.IsTLS13
}

// IsTLS13CipherSuite checks if a cipher suite belongs to TLS 1.3
func IsTLS13CipherSuite(cipherSuite uint16) bool {
	info := GetCipherSuiteInfo(cipherSuite)
	return info != nil && info.IsTLS13
}

// IsTLS12AESGCMCipherSuite checks if a cipher suite is a TLS 1.2 AES-GCM cipher suite
func IsTLS12AESGCMCipherSuite(cipherSuite uint16) bool {
	return IsTLS12CipherSuite(cipherSuite) && IsAESGCM(cipherSuite)
}

// IsTLS12ChaCha20Poly1305CipherSuite checks if a cipher suite is a TLS 1.2 ChaCha20-Poly1305 cipher suite
func IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite uint16) bool {
	return IsTLS12CipherSuite(cipherSuite) && IsChaCha20(cipherSuite)
}

// TLS 1.3 Extension Types
const (
	extensionServerName           = 0
	extensionSupportedGroups      = 10
	extensionECPointFormats       = 11
	extensionSignatureAlgorithms  = 13
	extensionHeartbeat            = 15
	extensionALPN                 = 16
	extensionEncryptThenMAC       = 22
	extensionExtendedMasterSecret = 23
	extensionSessionTicket        = 35
	extensionSupportedVersions    = 43
	extensionCookie               = 44
	extensionKeyShare             = 51
	extensionRenegotiationInfo    = 0xff01
)

// TLS 1.3 Supported Groups
const (
	secp256r1 = 23
	secp384r1 = 24
	secp521r1 = 25
	X25519    = 29
)

// Signature Algorithms (IANA TLS SignatureScheme Registry)
const (
	// ECDSA algorithms
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	ecdsa_secp521r1_sha512 = 0x0603

	// RSA-PSS algorithms with rsaEncryption OID (modern, preferred)
	rsa_pss_rsae_sha256 = 0x0804
	rsa_pss_rsae_sha384 = 0x0805
	rsa_pss_rsae_sha512 = 0x0806

	// RSA-PSS algorithms with id-RSASSA-PSS OID (newer certificates)
	rsa_pss_pss_sha256 = 0x0809
	rsa_pss_pss_sha384 = 0x080a
	rsa_pss_pss_sha512 = 0x080b

	// RSA-PKCS1 algorithms (older, but still widely supported)
	rsa_pkcs1_sha256 = 0x0401
	rsa_pkcs1_sha384 = 0x0501
	rsa_pkcs1_sha512 = 0x0601

	// EdDSA algorithms (modern, efficient)
	ed25519 = 0x0807
	ed448   = 0x0808
)

// TLS 1.3 Alert Levels
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2
)

// TLS 1.3 Alert Descriptions (from RFC 8446, Section 6)
const (
	alertCloseNotify                  = 0
	alertUnexpectedMessage            = 10
	alertBadRecordMAC                 = 20
	alertDecryptionFailed             = 21
	alertRecordOverflow               = 22
	alertDecompressionFailure         = 30
	alertHandshakeFailure             = 40
	alertBadCertificate               = 42
	alertUnsupportedCertificate       = 43
	alertCertificateRevoked           = 44
	alertCertificateExpired           = 45
	alertCertificateUnknown           = 46
	alertIllegalParameter             = 47
	alertUnknownCA                    = 48
	alertAccessDenied                 = 49
	alertDecodeError                  = 50
	alertDecryptError                 = 51
	alertProtocolVersion              = 70
	alertInsufficientSecurity         = 71
	alertInternalError                = 80
	alertInappropriateFallback        = 86
	alertUserCanceled                 = 90
	alertMissingExtension             = 109
	alertUnsupportedExtension         = 110
	alertCertificateUnobtainable      = 111
	alertUnrecognizedName             = 112
	alertBadCertificateStatusResponse = 113
	alertBadCertificateHashValue      = 114
	alertUnknownPSKIdentity           = 115
	alertCertificateRequired          = 116
	alertNoApplicationProtocol        = 120
)

type ClientHelloMsg struct {
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	serverName                   string
	supportedCurves              []uint16
	supportedSignatureAlgorithms []uint16
	alpnProtocols                []string
	supportedVersions            []uint16
	cookie                       []byte
	keyShares                    []keyShare
	extendedMasterSecret         bool
	encryptThenMAC               bool
}

func (m *ClientHelloMsg) Marshal() []byte {
	var b []byte
	// Handshake protocol header
	b = append(b, byte(typeClientHello), 0, 0, 0) // Message type and placeholder for length

	// TLS 1.2 compatibility version
	b = append(b, 0x03, 0x03)
	// Random
	b = append(b, m.random...)
	// Session ID
	b = append(b, byte(len(m.sessionId)))
	b = append(b, m.sessionId...)
	// Cipher suites
	b = append(b, byte(len(m.cipherSuites)*2>>8), byte(len(m.cipherSuites)*2))
	for _, suite := range m.cipherSuites {
		b = append(b, byte(suite>>8), byte(suite))
	}
	// Compression methods
	b = append(b, byte(len(m.compressionMethods)))
	b = append(b, m.compressionMethods...)

	// Extensions
	// RFC-compliant extension ordering for TLS 1.2:
	// 1. Server Name (0)
	// 2. Supported Groups (10)
	// 3. Signature Algorithms (13)
	// 4. Extended Master Secret (23)
	// 5. ALPN (16)
	// 6. Supported Versions (43)
	// 7. Key Share (51) - only for TLS 1.3
	var extensions []byte

	// 1. Server Name Indication (0)
	if len(m.serverName) > 0 {
		extensions = append(extensions, byte(extensionServerName>>8), byte(extensionServerName))
		extLen := len(m.serverName) + 5
		extensions = append(extensions, byte(extLen>>8), byte(extLen))
		listLen := len(m.serverName) + 3
		extensions = append(extensions, byte(listLen>>8), byte(listLen))
		extensions = append(extensions, 0) // Name type: host_name
		extensions = append(extensions, byte(len(m.serverName)>>8), byte(len(m.serverName)))
		extensions = append(extensions, m.serverName...)
	}

	// 3.5. Encrypt-then-MAC (22) - RFC 7366. A server may echo this
	// extension only when it selects a block-cipher suite.
	if m.encryptThenMAC {
		extensions = append(extensions, byte(extensionEncryptThenMAC>>8), byte(extensionEncryptThenMAC))
		extensions = append(extensions, 0, 0)
	}

	// 2. Supported Groups (10)
	if len(m.supportedCurves) > 0 {
		extensions = append(extensions, byte(extensionSupportedGroups>>8), byte(extensionSupportedGroups))
		groupsLen := len(m.supportedCurves) * 2
		extensions = append(extensions, byte((groupsLen+2)>>8), byte(groupsLen+2))
		extensions = append(extensions, byte(groupsLen>>8), byte(groupsLen))
		for _, group := range m.supportedCurves {
			extensions = append(extensions, byte(group>>8), byte(group))
		}
	}

	// 2.5. EC Point Formats (11) - RFC 4492
	// Always advertise support for uncompressed points (format 0)
	if len(m.supportedCurves) > 0 {
		extensions = append(extensions, byte(extensionECPointFormats>>8), byte(extensionECPointFormats))
		extensions = append(extensions, 0, 2) // Extension length: 2 bytes
		extensions = append(extensions, 1)    // EC point formats length: 1 byte
		extensions = append(extensions, 0)    // uncompressed (0)
	}

	// 3. Signature Algorithms (13)
	if len(m.supportedSignatureAlgorithms) > 0 {
		extensions = append(extensions, byte(extensionSignatureAlgorithms>>8), byte(extensionSignatureAlgorithms))
		sigAlgosLen := len(m.supportedSignatureAlgorithms) * 2
		extensions = append(extensions, byte((sigAlgosLen+2)>>8), byte(sigAlgosLen+2))
		extensions = append(extensions, byte(sigAlgosLen>>8), byte(sigAlgosLen))
		for _, algo := range m.supportedSignatureAlgorithms {
			extensions = append(extensions, byte(algo>>8), byte(algo))
		}
	}

	// 4. Extended Master Secret (23) - RFC 7627
	if m.extendedMasterSecret {
		extensions = append(extensions, byte(extensionExtendedMasterSecret>>8), byte(extensionExtendedMasterSecret))
		extensions = append(extensions, 0) // Extension length: 0
		extensions = append(extensions, 0) // Extension data: empty
	}

	// 4.5. Heartbeat (15) - RFC 6520
	// Always opt out by sending peer_not_allowed_to_send (2) to prevent Heartbleed-style issues
	{
		extensions = append(extensions, byte(extensionHeartbeat>>8), byte(extensionHeartbeat))
		extensions = append(extensions, 0x00, 0x01) // Extension length: 1 byte
		extensions = append(extensions, 0x02)       // peer_not_allowed_to_send
	}

	// 4.6. Secure Renegotiation (0xff01) - RFC 5746
	// Always send empty renegotiation_info in initial handshake to prevent downgrade attacks
	{
		extensions = append(extensions, byte(extensionRenegotiationInfo>>8), byte(extensionRenegotiationInfo&0xff))
		extensions = append(extensions, 0x00, 0x01) // Extension length: 1 byte
		extensions = append(extensions, 0x00)       // Renegotiated connection length: 0 (initial)
	}

	// 5. ALPN (16) - Application-Layer Protocol Negotiation (RFC 7301)
	if len(m.alpnProtocols) > 0 {
		extensions = append(extensions, byte(extensionALPN>>8), byte(extensionALPN))

		// Calculate total ALPN list length
		alpnListLen := 0
		for _, proto := range m.alpnProtocols {
			alpnListLen += 1 + len(proto) // 1 byte length + protocol string
		}

		// Extension length = 2 bytes for list length + list data
		extLen := 2 + alpnListLen
		extensions = append(extensions, byte(extLen>>8), byte(extLen))

		// ALPN protocol list length
		extensions = append(extensions, byte(alpnListLen>>8), byte(alpnListLen))

		// Add each protocol: length (1 byte) + protocol string
		for _, proto := range m.alpnProtocols {
			extensions = append(extensions, byte(len(proto)))
			extensions = append(extensions, proto...)
		}
	}

	// 6. Supported Versions (43)
	if len(m.supportedVersions) > 0 {
		extensions = append(extensions, byte(extensionSupportedVersions>>8), byte(extensionSupportedVersions))
		versionsLen := len(m.supportedVersions) * 2
		extensions = append(extensions, byte((versionsLen+1)>>8), byte(versionsLen+1))
		extensions = append(extensions, byte(versionsLen))
		for _, v := range m.supportedVersions {
			extensions = append(extensions, byte(v>>8), byte(v))
		}
	}

	// Cookie (44) is present in ClientHello2 only when supplied by an HRR.
	if len(m.cookie) > 0 {
		extensions = append(extensions, byte(extensionCookie>>8), byte(extensionCookie))
		extLen := len(m.cookie) + 2
		extensions = append(extensions, byte(extLen>>8), byte(extLen))
		extensions = append(extensions, byte(len(m.cookie)>>8), byte(len(m.cookie)))
		extensions = append(extensions, m.cookie...)
	}

	// 7. Key Share (51) - only for TLS 1.3
	// Only send key_share extension if TLS 1.3 is advertised in supported_versions
	if len(m.keyShares) > 0 {
		// Check if TLS 1.3 (0x0304) is in the supported versions
		hasTLS13 := slices.Contains(m.supportedVersions, VersionTLS13)

		// Only include key_share if advertising TLS 1.3 support
		if hasTLS13 {
			extensions = append(extensions, byte(extensionKeyShare>>8), byte(extensionKeyShare))
			var keySharesLen uint16
			for _, ks := range m.keyShares {
				keySharesLen += 2 + 2 + uint16(len(ks.data))
			}
			extensions = append(extensions, byte((keySharesLen+2)>>8), byte(keySharesLen+2))
			extensions = append(extensions, byte(keySharesLen>>8), byte(keySharesLen))
			for _, ks := range m.keyShares {
				extensions = append(extensions, byte(ks.group>>8), byte(ks.group))
				extensions = append(extensions, byte(len(ks.data)>>8), byte(len(ks.data)))
				extensions = append(extensions, ks.data...)
			}
		}
	}

	// Append extensions
	b = append(b, byte(len(extensions)>>8), byte(len(extensions)))
	b = append(b, extensions...)

	// Set message length
	putUint24(b[1:4], uint32(len(b)-4))

	// Prepend record header - use TLS 1.2 for the record layer
	record := []byte{recordTypeHandshake, 0x03, 0x03, byte(len(b) >> 8), byte(len(b))}
	record = append(record, b...)

	return record
}

func putUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func AlertDescriptionString(d uint8) string {
	switch d {
	case alertCloseNotify:
		return "close_notify"
	case alertUnexpectedMessage:
		return "unexpected_message"
	case alertBadRecordMAC:
		return "bad_record_mac"
	case alertDecryptionFailed:
		return "decryption_failed"
	case alertRecordOverflow:
		return "record_overflow"
	case alertDecompressionFailure:
		return "decompression_failure"
	case alertHandshakeFailure:
		return "handshake_failure"
	case alertBadCertificate:
		return "bad_certificate"
	case alertUnsupportedCertificate:
		return "unsupported_certificate"
	case alertCertificateRevoked:
		return "certificate_revoked"
	case alertCertificateExpired:
		return "certificate_expired"
	case alertCertificateUnknown:
		return "certificate_unknown"
	case alertIllegalParameter:
		return "illegal_parameter"
	case alertUnknownCA:
		return "unknown_ca"
	case alertAccessDenied:
		return "access_denied"
	case alertDecodeError:
		return "decode_error"
	case alertDecryptError:
		return "decrypt_error"
	case alertProtocolVersion:
		return "protocol_version"
	case alertInsufficientSecurity:
		return "insufficient_security"
	case alertInternalError:
		return "internal_error"
	case alertInappropriateFallback:
		return "inappropriate_fallback"
	case alertUserCanceled:
		return "user_canceled"
	case alertMissingExtension:
		return "missing_extension"
	case alertUnsupportedExtension:
		return "unsupported_extension"
	case alertCertificateUnobtainable:
		return "certificate_unobtainable"
	case alertUnrecognizedName:
		return "unrecognized_name"
	case alertBadCertificateStatusResponse:
		return "bad_certificate_status_response"
	case alertBadCertificateHashValue:
		return "bad_certificate_hash_value"
	case alertUnknownPSKIdentity:
		return "unknown_psk_identity"
	case alertCertificateRequired:
		return "certificate_required"
	case alertNoApplicationProtocol:
		return "no_application_protocol"
	default:
		return "unknown"
	}
}
