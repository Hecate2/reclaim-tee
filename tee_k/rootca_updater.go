package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	checksum []byte // SHA1 checksum
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
	logger.Info("Starting root CA update from Alpine packages")

	pemData, err := fetchAndVerifyAlpineCACerts(logger)
	if err != nil {
		logger.Warn("Root CA update failed, keeping existing certs", zap.Error(err))
		return
	}

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

	logger.Info("Root CA pool updated successfully", zap.Int("size_bytes", len(pemData)))
}

func fetchAndVerifyAlpineCACerts(logger *shared.Logger) ([]byte, error) {
	client := &http.Client{Timeout: fetchTimeout}

	// 1. Fetch and verify APKINDEX to get package info
	pkg, err := getPackageInfo(client, logger)
	if err != nil {
		return nil, fmt.Errorf("get package info: %w", err)
	}

	logger.Info("Found ca-certificates-bundle package", zap.String("filename", pkg.filename))

	// 2. Fetch the package
	pkgURL := alpineMirror + pkg.filename
	pkgData, err := fetchWithLimit(client, pkgURL, maxPackageSize)
	if err != nil {
		return nil, fmt.Errorf("fetch package: %w", err)
	}

	// 3. Verify package checksum (from signed index)
	// The checksum is SHA1 of the control stream only (stream 2), not the whole file
	controlStream, err := extractControlStream(pkgData)
	if err != nil {
		return nil, fmt.Errorf("extract control stream: %w", err)
	}
	actualHash := sha1.Sum(controlStream)
	if !bytes.Equal(actualHash[:], pkg.checksum) {
		return nil, fmt.Errorf("checksum mismatch")
	}
	logger.Info("Package checksum verified")

	// 4. Extract ca-certificates.crt from package
	certsPEM, err := extractCertsFromAPK(pkgData)
	if err != nil {
		return nil, fmt.Errorf("extract certs: %w", err)
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
	// Find the boundary between two gzip streams
	streamBoundary, err := findGzipStreamBoundary(data)
	if err != nil {
		return nil, fmt.Errorf("find stream boundary: %w", err)
	}

	// Stream 1: signature
	sigStream := data[:streamBoundary]
	// Stream 2: signed index data
	indexStream := data[streamBoundary:]

	// Extract signature from stream 1
	signature, keyName, err := extractSignatureFromStream(sigStream)
	if err != nil {
		return nil, fmt.Errorf("extract signature: %w", err)
	}

	// Verify signature over stream 2 raw bytes
	if err := verifySignature(indexStream, signature, keyName, logger); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	// Parse stream 2 to get package info
	return parseIndexStream(indexStream)
}

// findGzipStreamBoundary finds where the first gzip stream ends.
// Gzip streams can be detected by decompressing and tracking position.
func findGzipStreamBoundary(data []byte) (int, error) {
	// Look for gzip magic (1f 8b 08) after position 0
	// The boundary is where a valid gzip header appears after the first stream
	for i := 1; i < len(data)-2; i++ {
		if data[i] == 0x1f && data[i+1] == 0x8b && data[i+2] == 0x08 {
			// Verify this is actually a stream boundary by checking
			// if the previous 8 bytes could be a gzip footer
			if i >= 8 {
				// Try to decompress stream 1
				gz, err := gzip.NewReader(bytes.NewReader(data[:i]))
				if err == nil {
					_, err = io.ReadAll(gz)
					gz.Close()
					if err == nil {
						return i, nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("no second gzip stream found")
}

// extractSignatureFromStream extracts the signature from the first gzip stream.
func extractSignatureFromStream(data []byte) ([]byte, string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tarContent, err := io.ReadAll(gz)
	if err != nil {
		return nil, "", fmt.Errorf("decompress: %w", err)
	}

	tr := tar.NewReader(bytes.NewReader(tarContent))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("tar read: %w", err)
		}

		if strings.HasPrefix(hdr.Name, ".SIGN.RSA.") {
			sig, err := io.ReadAll(tr)
			if err != nil {
				return nil, "", fmt.Errorf("read signature: %w", err)
			}
			keyName := strings.TrimPrefix(hdr.Name, ".SIGN.RSA.")
			return sig, keyName, nil
		}
	}

	return nil, "", fmt.Errorf("no signature file found")
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

	logger.Info("APKINDEX signature verified", zap.String("key", keyName))
	return nil
}

// parseIndexStream parses the index gzip stream to find package info.
func parseIndexStream(data []byte) (*pkgInfo, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}

		if hdr.Name == "APKINDEX" {
			content, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read APKINDEX: %w", err)
			}
			return findPackageInIndex(content)
		}
	}

	return nil, fmt.Errorf("APKINDEX not found")
}

func findPackageInIndex(content []byte) (*pkgInfo, error) {
	// APKINDEX format: blocks separated by blank lines
	// C:checksum (base64 encoded, Q1 prefix = SHA1)
	// P:package-name
	// V:version
	blocks := strings.Split(string(content), "\n\n")

	for _, block := range blocks {
		lines := strings.Split(block, "\n")
		var name, version, checksumStr string

		for _, line := range lines {
			if strings.HasPrefix(line, "P:") {
				name = strings.TrimPrefix(line, "P:")
			} else if strings.HasPrefix(line, "V:") {
				version = strings.TrimPrefix(line, "V:")
			} else if strings.HasPrefix(line, "C:") {
				checksumStr = strings.TrimPrefix(line, "C:")
			}
		}

		if name == caCertsPkg {
			// Checksum format: Q1<base64 SHA1> (Q1 prefix indicates SHA1)
			if !strings.HasPrefix(checksumStr, "Q1") {
				return nil, fmt.Errorf("unsupported checksum format: %s", checksumStr)
			}

			checksum, err := base64.StdEncoding.DecodeString(checksumStr[2:])
			if err != nil {
				return nil, fmt.Errorf("decode checksum: %w", err)
			}

			return &pkgInfo{
				filename: fmt.Sprintf("%s-%s.apk", name, version),
				checksum: checksum,
			}, nil
		}
	}

	return nil, fmt.Errorf("package %s not found in index", caCertsPkg)
}

// extractControlStream extracts the control stream (stream 2) from an APK package.
// APK packages have 3 concatenated gzip streams:
//   - Stream 1: Signature segment (.SIGN.RSA.*)
//   - Stream 2: Control segment (.PKGINFO, scripts)
//   - Stream 3: Data segment (actual files)
//
// The APKINDEX checksum is SHA1 of the raw bytes of stream 2.
func extractControlStream(pkgData []byte) ([]byte, error) {
	// Find all gzip stream boundaries (magic bytes: 1f 8b 08)
	var boundaries []int
	for i := 0; i < len(pkgData)-2; i++ {
		if pkgData[i] == 0x1f && pkgData[i+1] == 0x8b && pkgData[i+2] == 0x08 {
			boundaries = append(boundaries, i)
		}
	}

	if len(boundaries) < 3 {
		return nil, fmt.Errorf("APK must have at least 3 gzip streams, found %d", len(boundaries))
	}

	// Stream 2 is between boundaries[1] and boundaries[2]
	stream2Start := boundaries[1]
	stream2End := boundaries[2]

	return pkgData[stream2Start:stream2End], nil
}

func extractCertsFromAPK(pkgData []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(pkgData))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Look for the certs file
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == certsPathInPkg {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("certificate file not found in package")
}
