package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
)

const testAlpineKeyName = "rootca-updater-test.rsa.pub"

type testTarEntry struct {
	name string
	body []byte
}

type testAPK struct {
	pkg       *pkgInfo
	signature []byte
	control   []byte
	data      []byte
	certs     []byte
}

func TestVerifyAndExtractCACerts(t *testing.T) {
	privateKey := installTestAlpineKey(t)
	fixture := makeTestAPK(t, privateKey)
	logger := &shared.Logger{Logger: zap.NewNop()}

	t.Run("valid package", func(t *testing.T) {
		got, err := verifyAndExtractCACerts(fixture.bytes(), fixture.pkg, logger)
		if err != nil {
			t.Fatalf("verify package: %v", err)
		}
		if !bytes.Equal(got, fixture.certs) {
			t.Fatalf("CA bundle mismatch: got %q, want %q", got, fixture.certs)
		}
	})

	t.Run("replaced data member", func(t *testing.T) {
		attackerData := gzipTar(t, []testTarEntry{{name: certsPathInPkg, body: []byte("attacker CA")}}, false)
		_, err := verifyAndExtractCACerts(bytes.Join([][]byte{fixture.signature, fixture.control, attackerData}, nil), fixture.pkg, logger)
		if err == nil || !strings.Contains(err.Error(), "datahash mismatch") {
			t.Fatalf("got %v, want datahash mismatch", err)
		}
	})

	t.Run("mismatched package identity", func(t *testing.T) {
		wrong := *fixture.pkg
		wrong.version = "different-r0"
		_, err := verifyAndExtractCACerts(fixture.bytes(), &wrong, logger)
		if err == nil || !strings.Contains(err.Error(), "package metadata mismatch") {
			t.Fatalf("got %v, want package metadata mismatch", err)
		}
	})

	t.Run("extra signature entry", func(t *testing.T) {
		badSignature := gzipTar(t, []testTarEntry{
			{name: ".SIGN.RSA." + testAlpineKeyName, body: []byte("signature")},
			{name: "unexpected", body: []byte("entry")},
		}, true)
		_, err := verifyAndExtractCACerts(bytes.Join([][]byte{badSignature, fixture.control, fixture.data}, nil), fixture.pkg, logger)
		if err == nil || !strings.Contains(err.Error(), "unexpected signature member entry") {
			t.Fatalf("got %v, want unexpected signature entry error", err)
		}
	})

	t.Run("extra gzip member", func(t *testing.T) {
		extra := gzipTar(t, []testTarEntry{{name: "extra", body: []byte("entry")}}, false)
		_, err := verifyAndExtractCACerts(append(fixture.bytes(), extra...), fixture.pkg, logger)
		if err == nil || !strings.Contains(err.Error(), "too many gzip members") {
			t.Fatalf("got %v, want extra member error", err)
		}
	})
}

func TestParseAndVerifyIndex(t *testing.T) {
	privateKey := installTestAlpineKey(t)
	fixture := makeTestAPK(t, privateKey)
	controlHash := sha1.Sum(fixture.control)
	index := fmt.Sprintf("C:Q1%s\nP:%s\nV:%s\nA:%s\nT:contains gzip magic: %s\n\n",
		base64.StdEncoding.EncodeToString(controlHash[:]), fixture.pkg.name, fixture.pkg.version,
		fixture.pkg.arch, string([]byte{0x1f, 0x8b, 0x08}))
	indexMember := gzipTar(t, []testTarEntry{
		{name: "DESCRIPTION", body: []byte("test repository")},
		{name: "APKINDEX", body: []byte(index)},
	}, false)
	signature := signGzipMember(t, privateKey, indexMember)

	got, err := parseAndVerifyIndex(append(signature, indexMember...), &shared.Logger{Logger: zap.NewNop()})
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if got.filename != fixture.pkg.filename || got.name != fixture.pkg.name ||
		got.version != fixture.pkg.version || got.arch != fixture.pkg.arch ||
		!bytes.Equal(got.checksum, controlHash[:]) {
		t.Fatalf("unexpected package info: %#v", got)
	}
}

func TestSplitGzipMembersRejectsCorruptMember(t *testing.T) {
	member := gzipTar(t, []testTarEntry{{name: "file", body: []byte("contents")}}, false)
	member[len(member)-1] ^= 0xff
	if _, err := splitGzipMembers(member, 1); err == nil {
		t.Fatal("corrupt gzip member accepted")
	}
}

// TestAlpineParserArtifacts validates locally downloaded, matching APKINDEX and
// package files. It is opt-in so the normal test suite remains hermetic.
func TestAlpineParserArtifacts(t *testing.T) {
	indexPath := os.Getenv("TEST_ALPINE_APKINDEX")
	packagePath := os.Getenv("TEST_ALPINE_APK")
	if indexPath == "" || packagePath == "" {
		t.Skip("set TEST_ALPINE_APKINDEX and TEST_ALPINE_APK")
	}
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	pkg, err := parseAndVerifyIndex(indexData, &shared.Logger{Logger: zap.NewNop()})
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	packageData, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	certs, err := verifyAndExtractCACerts(packageData, pkg, &shared.Logger{Logger: zap.NewNop()})
	if err != nil {
		t.Fatalf("verify package: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("empty CA bundle")
	}
}

func installTestAlpineKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	alpineSigningKeys[testAlpineKeyName] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	t.Cleanup(func() { delete(alpineSigningKeys, testAlpineKeyName) })
	return privateKey
}

func makeTestAPK(t *testing.T, privateKey *rsa.PrivateKey) *testAPK {
	t.Helper()
	certs := []byte("test CA bundle\nwith embedded gzip magic: \x1f\x8b\x08\n")
	data := gzipTar(t, []testTarEntry{{name: certsPathInPkg, body: certs}}, false)
	dataHash := sha256.Sum256(data)
	metadata := fmt.Sprintf("pkgname = %s\npkgver = 20260611-r0\narch = noarch\ndatahash = %s\n",
		caCertsPkg, hex.EncodeToString(dataHash[:]))
	control := gzipTar(t, []testTarEntry{{name: ".PKGINFO", body: []byte(metadata)}}, true)
	controlHash := sha1.Sum(control)
	return &testAPK{
		pkg: &pkgInfo{
			filename: caCertsPkg + "-20260611-r0.apk",
			name:     caCertsPkg,
			version:  "20260611-r0",
			arch:     "x86_64",
			checksum: controlHash[:],
		},
		signature: signGzipMember(t, privateKey, control),
		control:   control,
		data:      data,
		certs:     certs,
	}
}

func (a *testAPK) bytes() []byte {
	return bytes.Join([][]byte{a.signature, a.control, a.data}, nil)
}

func signGzipMember(t *testing.T, privateKey *rsa.PrivateKey, member []byte) []byte {
	t.Helper()
	digest := sha1.Sum(member)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest[:])
	if err != nil {
		t.Fatalf("sign member: %v", err)
	}
	return gzipTar(t, []testTarEntry{{name: ".SIGN.RSA." + testAlpineKeyName, body: signature}}, true)
}

func gzipTar(t *testing.T, entries []testTarEntry, segment bool) []byte {
	t.Helper()
	var tarBuffer bytes.Buffer
	tw := tar.NewWriter(&tarBuffer)
	for _, entry := range entries {
		hdr := &tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	tarData := tarBuffer.Bytes()
	if segment {
		const tarEOFSize = 2 * 512
		if len(tarData) < tarEOFSize || !bytes.Equal(tarData[len(tarData)-tarEOFSize:], make([]byte, tarEOFSize)) {
			t.Fatal("tar writer did not produce expected EOF blocks")
		}
		tarData = tarData[:len(tarData)-tarEOFSize]
	}

	var gzipBuffer bytes.Buffer
	gw := gzip.NewWriter(&gzipBuffer)
	if _, err := gw.Write(tarData); err != nil {
		t.Fatalf("write gzip member: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip member: %v", err)
	}
	return gzipBuffer.Bytes()
}
