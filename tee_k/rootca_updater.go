package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	alpineMirror   = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/"
	apkIndexFile   = "APKINDEX.tar.gz"
	caCertsPkg     = "ca-certificates-bundle"
	updatePeriod   = 24 * time.Hour
	fetchTimeout   = 30 * time.Second
	maxPackageSize = 10 * 1024 * 1024 // 10MB max
	maxIndexSize   = 5 * 1024 * 1024  // 5MB max
	certsPathInPkg = "etc/ssl/certs/ca-certificates.crt"

	// Every gzip member is fully consumed once while splitting so its checksum
	// is verified and a compressed bomb cannot consume unbounded CPU. Individual
	// files have tighter limits below.
	maxGzipMemberExpandedSize = 64 * 1024 * 1024
	maxIndexFileSize          = 16 * 1024 * 1024
	maxPackageInfoSize        = 1 * 1024 * 1024
	maxCABundleSize           = 4 * 1024 * 1024
	maxSignatureSize          = 8 * 1024
)

// Alpine signing keys (4096-bit RSA)
// Downloaded from https://alpinelinux.org/keys/
var alpineSigningKeys = map[string]string{
	"alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAutQkua2CAig4VFSJ7v54
ALyu/J1WB3oni7qwCZD3veURw7HxpNAj9hR+S5N/pNeZgubQvJWyaPuQDm7PTs1+
tFGiYNfAsiibX6Rv0wci3M+z2XEVAeR9Vzg6v4qoofDyoTbovn2LztaNEjTkB+oK
tlvpNhg1zhou0jDVYFniEXvzjckxswHVb8cT0OMTKHALyLPrPOJzVtM9C1ew2Nnc
3848xLiApMu3NBk0JqfcS3Bo5Y2b1FRVBvdt+2gFoKZix1MnZdAEZ8xQzL/a0YS5
Hd0wj5+EEKHfOd3A75uPa/WQmA+o0cBFfrzm69QDcSJSwGpzWrD1ScH3AK8nWvoj
v7e9gukK/9yl1b4fQQ00vttwJPSgm9EnfPHLAtgXkRloI27H6/PuLoNvSAMQwuCD
hQRlyGLPBETKkHeodfLoULjhDi1K2gKJTMhtbnUcAA7nEphkMhPWkBpgFdrH+5z4
Lxy+3ek0cqcI7K68EtrffU8jtUj9LFTUC8dERaIBs7NgQ/LfDbDfGh9g6qVj1hZl
k9aaIPTm/xsi8v3u+0qaq7KzIBc9s59JOoA8TlpOaYdVgSQhHHLBaahOuAigH+VI
isbC9vmqsThF2QdDtQt37keuqoda2E6sL7PUvIyVXDRfwX7uMDjlzTxHTymvq2Ck
htBqojBnThmjJQFgZXocHG8CAwEAAQ==
-----END PUBLIC KEY-----`,
	"alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlEyxkHggKCXC2Wf5Mzx4
nZLFZvU2bgcA3exfNPO/g1YunKfQY+Jg4fr6tJUUTZ3XZUrhmLNWvpvSwDS19ZmC
IXOu0+V94aNgnhMsk9rr59I8qcbsQGIBoHzuAl8NzZCgdbEXkiY90w1skUw8J57z
qCsMBydAueMXuWqF5nGtYbi5vHwK42PffpiZ7G5Kjwn8nYMW5IZdL6ZnMEVJUWC9
I4waeKg0yskczYDmZUEAtrn3laX9677ToCpiKrvmZYjlGl0BaGp3cxggP2xaDbUq
qfFxWNgvUAb3pXD09JM6Mt6HSIJaFc9vQbrKB9KT515y763j5CC2KUsilszKi3mB
HYe5PoebdjS7D1Oh+tRqfegU2IImzSwW3iwA7PJvefFuc/kNIijfS/gH/cAqAK6z
bhdOtE/zc7TtqW2Wn5Y03jIZdtm12CxSxwgtCF1NPyEWyIxAQUX9ACb3M0FAZ61n
fpPrvwTaIIxxZ01L3IzPLpbc44x/DhJIEU+iDt6IMTrHOphD9MCG4631eIdB0H1b
6zbNX1CXTsafqHRFV9XmYYIeOMggmd90s3xIbEujA6HKNP/gwzO6CDJ+nHFDEqoF
SkxRdTkEqjTjVKieURW7Swv7zpfu5PrsrrkyGnsRrBJJzXlm2FOOxnbI2iSL1B5F
rO5kbUxFeZUIDq+7Yv4kLWcCAwEAAQ==
-----END PUBLIC KEY-----`,
}

type pkgInfo struct {
	filename string
	name     string
	version  string
	arch     string
	checksum []byte // SHA1 checksum
}

type packageMetadata struct {
	name     string
	version  string
	arch     string
	dataHash [sha256.Size]byte
}

// StartRootCAUpdater starts the background goroutine that updates root CAs.
// Runs immediately on start, then periodically.
// Never crashes - all errors are logged and ignored.
func StartRootCAUpdater(logger *shared.Logger) {
	go func() {
		// Run immediately on startup
		updateRootCAs(logger)

		ticker := time.NewTicker(updatePeriod)
		defer ticker.Stop()

		for range ticker.C {
			updateRootCAs(logger)
		}
	}()
}

func updateRootCAs(logger *shared.Logger) {
	logger.Debug("Starting root CA update from Alpine packages")

	pemData, err := fetchAndVerifyAlpineCACerts(logger)
	if err != nil {
		logger.Warn("Root CA update failed, keeping existing certs", zap.Error(err))
		return
	}

	// Count certificates before adding them to pool
	certCount := 0
	pemCopy := pemData
	for {
		block, rest := pem.Decode(pemCopy)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
		}
		pemCopy = rest
	}
	logger.Debug("Root CA certificates loaded", zap.Int("cert_count", certCount))

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		logger.Warn("Failed to parse fetched CA certificates, keeping existing certs")
		return
	}

	// Update shared pool (used by minitls and custom transports via shared.GetTLSConfig())
	shared.SetRootCAPool(pool)

	// Also update defaults for any code using them
	tlsConfig := &tls.Config{RootCAs: pool}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.TLSClientConfig = tlsConfig
	}
	websocket.DefaultDialer.TLSClientConfig = tlsConfig

	logger.Debug("Root CA pool updated successfully", zap.Int("size_bytes", len(pemData)))
}

func fetchAndVerifyAlpineCACerts(logger *shared.Logger) ([]byte, error) {
	client := &http.Client{Timeout: fetchTimeout}

	// 1. Fetch and verify APKINDEX to get package info
	pkg, err := getPackageInfo(client, logger)
	if err != nil {
		return nil, fmt.Errorf("get package info: %w", err)
	}

	logger.Debug("Found ca-certificates-bundle package", zap.String("filename", pkg.filename))

	// 2. Fetch the package
	pkgURL := alpineMirror + pkg.filename
	pkgData, err := fetchWithLimit(client, pkgURL, maxPackageSize)
	if err != nil {
		return nil, fmt.Errorf("fetch package: %w", err)
	}

	// Verify the package signature and the complete APKINDEX -> control -> data
	// hash chain before reading the CA bundle from the data member.
	certsPEM, err := verifyAndExtractCACerts(pkgData, pkg, logger)
	if err != nil {
		return nil, fmt.Errorf("verify package: %w", err)
	}

	return certsPEM, nil
}

func getPackageInfo(client *http.Client, logger *shared.Logger) (*pkgInfo, error) {
	indexURL := alpineMirror + apkIndexFile
	indexData, err := fetchWithLimit(client, indexURL, maxIndexSize)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}

	// Parse and verify index (two concatenated gzip streams)
	return parseAndVerifyIndex(indexData, logger)
}

func fetchWithLimit(client *http.Client, url string, maxSize int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) == maxSize {
		return nil, fmt.Errorf("response exceeds max size %d", maxSize)
	}

	return data, nil
}

// parseAndVerifyIndex parses a signed APKINDEX.tar.gz file.
// Format: two concatenated gzip streams:
//   - Stream 1: tar segment with .SIGN.RSA.<keyname> file
//   - Stream 2: original index tar (DESCRIPTION + APKINDEX)
//
// The signature is over the raw bytes of stream 2.
func parseAndVerifyIndex(data []byte, logger *shared.Logger) (*pkgInfo, error) {
	members, err := splitGzipMembers(data, 2)
	if err != nil {
		return nil, fmt.Errorf("split index members: %w", err)
	}

	signature, keyName, err := extractSignatureFromMember(members[0])
	if err != nil {
		return nil, fmt.Errorf("extract signature: %w", err)
	}

	// Alpine signs the exact compressed index member, not its decompressed tar.
	if err := verifySignature(members[1], signature, keyName, logger); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	return parseIndexMember(members[1])
}

// splitGzipMembers separates concatenated gzip members without searching for
// gzip magic bytes inside compressed data. bytes.Reader implements io.ByteReader,
// so Multistream(false) leaves it positioned exactly after each member.
func splitGzipMembers(data []byte, expected int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty gzip input")
	}

	r := bytes.NewReader(data)
	members := make([][]byte, 0, expected)
	for r.Len() > 0 {
		if len(members) == expected {
			return nil, fmt.Errorf("too many gzip members: expected %d", expected)
		}
		start := len(data) - r.Len()
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("member %d header: %w", len(members)+1, err)
		}
		gz.Multistream(false)
		n, readErr := io.Copy(io.Discard, io.LimitReader(gz, maxGzipMemberExpandedSize+1))
		closeErr := gz.Close()
		if readErr != nil {
			return nil, fmt.Errorf("member %d decompress: %w", len(members)+1, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("member %d close: %w", len(members)+1, closeErr)
		}
		if n > maxGzipMemberExpandedSize {
			return nil, fmt.Errorf("member %d expands beyond %d bytes", len(members)+1, maxGzipMemberExpandedSize)
		}
		end := len(data) - r.Len()
		if end <= start {
			return nil, fmt.Errorf("member %d made no progress", len(members)+1)
		}
		members = append(members, data[start:end])
	}
	if len(members) != expected {
		return nil, fmt.Errorf("wrong gzip member count: got %d, want %d", len(members), expected)
	}
	return members, nil
}

// extractSignatureFromMember extracts the sole signature entry from a gzip
// member. Alpine signature members are tar segments and may omit tar EOF blocks.
func extractSignatureFromMember(member []byte) ([]byte, string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(member))
	if err != nil {
		return nil, "", fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	gz.Multistream(false)

	tr := tar.NewReader(gz)
	var signature []byte
	var keyName string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("tar read: %w", err)
		}

		if !strings.HasPrefix(hdr.Name, ".SIGN.RSA.") {
			return nil, "", fmt.Errorf("unexpected signature member entry %q", hdr.Name)
		}
		if signature != nil {
			return nil, "", fmt.Errorf("multiple signature entries")
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, "", fmt.Errorf("signature is not a regular file")
		}
		if hdr.Size <= 0 || hdr.Size > maxSignatureSize {
			return nil, "", fmt.Errorf("signature size %d is invalid", hdr.Size)
		}
		signature, err = io.ReadAll(tr)
		if err != nil {
			return nil, "", fmt.Errorf("read signature: %w", err)
		}
		keyName = strings.TrimPrefix(hdr.Name, ".SIGN.RSA.")
	}

	if signature == nil {
		return nil, "", fmt.Errorf("no signature file found")
	}
	return signature, keyName, nil
}

func verifySignature(data, signature []byte, keyName string, logger *shared.Logger) error {
	keyPEM, ok := alpineSigningKeys[keyName]
	if !ok {
		return fmt.Errorf("unknown signing key: %s", keyName)
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA key")
	}

	// Signature is PKCS1v15 RSA-SHA1 over the raw gzip bytes
	hash := sha1.Sum(data)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, hash[:], signature); err != nil {
		return fmt.Errorf("signature invalid: %w", err)
	}

	logger.Debug("Alpine signature verified", zap.String("key", keyName))
	return nil
}

func parseIndexMember(member []byte) (*pkgInfo, error) {
	content, err := readTarMemberFile(member, "APKINDEX", maxIndexFileSize)
	if err != nil {
		return nil, fmt.Errorf("read APKINDEX: %w", err)
	}
	return findPackageInIndex(content)
}

func findPackageInIndex(content []byte) (*pkgInfo, error) {
	// APKINDEX format: blocks separated by blank lines
	// C:checksum (base64 encoded, Q1 prefix = SHA1)
	// P:package-name
	// V:version
	blocks := strings.SplitSeq(string(content), "\n\n")

	for block := range blocks {
		lines := strings.Split(block, "\n")
		var name, version, arch, checksumStr string

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "P:"); ok {
				name = after
			} else if after, ok := strings.CutPrefix(line, "V:"); ok {
				version = after
			} else if after, ok := strings.CutPrefix(line, "A:"); ok {
				arch = after
			} else if after, ok := strings.CutPrefix(line, "C:"); ok {
				checksumStr = after
			}
		}

		if name == caCertsPkg {
			// Checksum format: Q1<base64 SHA1> (Q1 prefix indicates SHA1)
			if !strings.HasPrefix(checksumStr, "Q1") {
				return nil, fmt.Errorf("unsupported checksum format: %s", checksumStr)
			}

			checksum, err := base64.StdEncoding.Strict().DecodeString(checksumStr[2:])
			if err != nil {
				return nil, fmt.Errorf("decode checksum: %w", err)
			}
			if len(checksum) != sha1.Size {
				return nil, fmt.Errorf("checksum has %d bytes, want %d", len(checksum), sha1.Size)
			}
			if version == "" || arch == "" {
				return nil, fmt.Errorf("package %s is missing version or architecture", name)
			}

			return &pkgInfo{
				filename: fmt.Sprintf("%s-%s.apk", name, version),
				name:     name,
				version:  version,
				arch:     arch,
				checksum: checksum,
			}, nil
		}
	}

	return nil, fmt.Errorf("package %s not found in index", caCertsPkg)
}

// verifyAndExtractCACerts authenticates all three APK v2 members. The signed
// index pins the compressed control member via Q1/SHA-1; the control member's
// .PKGINFO pins the compressed data member via datahash/SHA-256.
func verifyAndExtractCACerts(pkgData []byte, pkg *pkgInfo, logger *shared.Logger) ([]byte, error) {
	members, err := splitGzipMembers(pkgData, 3)
	if err != nil {
		return nil, fmt.Errorf("split package members: %w", err)
	}

	signature, keyName, err := extractSignatureFromMember(members[0])
	if err != nil {
		return nil, fmt.Errorf("extract package signature: %w", err)
	}
	if err := verifySignature(members[1], signature, keyName, logger); err != nil {
		return nil, fmt.Errorf("package signature: %w", err)
	}

	controlHash := sha1.Sum(members[1])
	if !bytes.Equal(controlHash[:], pkg.checksum) {
		return nil, fmt.Errorf("control checksum mismatch")
	}

	pkgInfoData, err := readTarMemberFile(members[1], ".PKGINFO", maxPackageInfoSize)
	if err != nil {
		return nil, fmt.Errorf("read .PKGINFO: %w", err)
	}
	metadata, err := parsePackageMetadata(pkgInfoData)
	if err != nil {
		return nil, fmt.Errorf("parse .PKGINFO: %w", err)
	}
	// The repository index uses its repository architecture for noarch packages
	// (for example, x86_64 in APKINDEX and noarch in .PKGINFO). The signed index
	// checksum already pins this exact control member, so compare the package
	// identity fields that must be identical instead of rejecting valid noarch
	// packages.
	if metadata.name != pkg.name || metadata.version != pkg.version {
		return nil, fmt.Errorf("package metadata mismatch: got %s-%s, want %s-%s",
			metadata.name, metadata.version, pkg.name, pkg.version)
	}

	dataHash := sha256.Sum256(members[2])
	if !bytes.Equal(dataHash[:], metadata.dataHash[:]) {
		return nil, fmt.Errorf("datahash mismatch")
	}

	certs, err := readTarMemberFile(members[2], certsPathInPkg, maxCABundleSize)
	if err != nil {
		return nil, fmt.Errorf("extract CA bundle: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("CA bundle is empty")
	}
	return certs, nil
}

func parsePackageMetadata(data []byte) (*packageMetadata, error) {
	values := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("malformed metadata line %q", line)
		}
		if key == "pkgname" || key == "pkgver" || key == "arch" || key == "datahash" {
			if _, duplicate := values[key]; duplicate {
				return nil, fmt.Errorf("duplicate %s field", key)
			}
			values[key] = value
		}
	}

	for _, key := range []string{"pkgname", "pkgver", "arch", "datahash"} {
		if values[key] == "" {
			return nil, fmt.Errorf("missing %s field", key)
		}
	}
	rawHash, err := hex.DecodeString(values["datahash"])
	if err != nil || len(rawHash) != sha256.Size {
		return nil, fmt.Errorf("datahash must be %d-byte hexadecimal SHA-256", sha256.Size)
	}
	metadata := &packageMetadata{name: values["pkgname"], version: values["pkgver"], arch: values["arch"]}
	copy(metadata.dataHash[:], rawHash)
	return metadata, nil
}

func readTarMemberFile(member []byte, wanted string, maxSize int64) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(member))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	gz.Multistream(false)

	tr := tar.NewReader(gz)
	var result []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != wanted {
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("duplicate %s entry", wanted)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("%s is not a regular file", wanted)
		}
		if hdr.Size < 0 || hdr.Size > maxSize {
			return nil, fmt.Errorf("%s size %d exceeds limit %d", wanted, hdr.Size, maxSize)
		}
		result, err = io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", wanted, err)
		}
	}
	if result == nil {
		return nil, fmt.Errorf("%s not found", wanted)
	}
	return result, nil
}
