package minitls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"hash"
	"io"
	"math"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

type hashWithoutConstantTimeSum struct{ hash.Hash }

func testTLS12CBCKeys(t *testing.T, suite uint16) *TLS12CBCKeys {
	t.Helper()
	info := GetCipherSuiteInfo(suite)
	if info == nil || !info.IsCBC {
		t.Fatalf("suite 0x%04x is not CBC", suite)
	}
	return &TLS12CBCKeys{
		ClientMACKey: bytes.Repeat([]byte{0x11}, info.MACSize),
		ServerMACKey: bytes.Repeat([]byte{0x22}, info.MACSize),
		ClientKey:    bytes.Repeat([]byte{0x33}, info.KeySize),
		ServerKey:    bytes.Repeat([]byte{0x44}, info.KeySize),
		ClientIV:     bytes.Repeat([]byte{0x55}, info.IVSize),
		ServerIV:     bytes.Repeat([]byte{0x66}, info.IVSize),
	}
}

func testTLS12CBCPeerForClientWrites(t *testing.T, keys *TLS12CBCKeys, suite uint16, mode TLS12CBCRecordMode) *TLS12CBCContext {
	t.Helper()
	peer, err := NewTLS12CBCReadContext(&TLS12CBCReadState{
		CipherSuite: suite,
		Mode:        mode,
		ReadKey:     keys.ClientKey,
		ReadMACKey:  keys.ClientMACKey,
		ReadIV:      keys.ClientIV,
	})
	if err != nil {
		t.Fatalf("create CBC peer: %v", err)
	}
	return peer
}

func TestTLS12CBCRecordRoundTrip(t *testing.T) {
	for _, suite := range tls12CBCCipherSuites() {
		for _, mode := range []TLS12CBCRecordMode{
			TLS12CBCRecordModeMACThenEncrypt,
			TLS12CBCRecordModeEncryptThenMAC,
		} {
			info := GetCipherSuiteInfo(suite)
			t.Run(info.Name+"/"+mode.String(), func(t *testing.T) {
				keys := testTLS12CBCKeys(t, suite)
				client, err := NewTLS12CBCContext(keys, suite, mode)
				if err != nil {
					t.Fatalf("create CBC context: %v", err)
				}
				client.random = bytes.NewReader(bytes.Repeat([]byte{0xa5}, 32))
				peer := testTLS12CBCPeerForClientWrites(t, keys, suite, mode)
				plaintext := []byte("GET /resource HTTP/1.1\r\nHost: example.com\r\n\r\n")

				record, err := client.EncryptRecord(recordTypeApplicationData, plaintext)
				if err != nil {
					t.Fatalf("encrypt CBC record: %v", err)
				}
				got, err := peer.DecryptRecord(record[:5], record[5:])
				if err != nil {
					t.Fatalf("decrypt CBC record: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext = %q, want %q", got, plaintext)
				}
				if client.GetWriteSequence() != 1 || peer.GetReadSequence() != 1 {
					t.Fatalf("sequence mismatch: write=%d read=%d", client.GetWriteSequence(), peer.GetReadSequence())
				}
			})
		}
	}
}

func TestTLS12CBCTamperingReturnsOneError(t *testing.T) {
	for _, mode := range []TLS12CBCRecordMode{
		TLS12CBCRecordModeMACThenEncrypt,
		TLS12CBCRecordModeEncryptThenMAC,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			var suite uint16 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			keys := testTLS12CBCKeys(t, suite)
			client, err := NewTLS12CBCContext(keys, suite, mode)
			if err != nil {
				t.Fatal(err)
			}
			client.random = bytes.NewReader(bytes.Repeat([]byte{0x7b}, 64))
			record, err := client.EncryptRecord(recordTypeApplicationData, bytes.Repeat([]byte("x"), 37))
			if err != nil {
				t.Fatal(err)
			}

			mutations := map[string]func([]byte){
				"content type": func(value []byte) { value[0] ^= 1 },
				"explicit IV":  func(value []byte) { value[5] ^= 1 },
				"ciphertext":   func(value []byte) { value[5+16] ^= 1 },
				"final byte":   func(value []byte) { value[len(value)-1] ^= 1 },
				"wire length":  func(value []byte) { value[4] ^= 1 },
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					peer := testTLS12CBCPeerForClientWrites(t, keys, suite, mode)
					tampered := append([]byte(nil), record...)
					mutate(tampered)
					_, err := peer.DecryptRecord(tampered[:5], tampered[5:])
					if !errors.Is(err, ErrBadRecordMAC) {
						t.Fatalf("error = %v, want ErrBadRecordMAC", err)
					}
					if peer.GetReadSequence() != 0 {
						t.Fatalf("failed record advanced sequence to %d", peer.GetReadSequence())
					}
				})
			}
		})
	}
}

func TestTLS12CBCReadStateIsDirectionalAndCloned(t *testing.T) {
	var suite uint16 = TLS_RSA_WITH_AES_128_CBC_SHA256
	keys := testTLS12CBCKeys(t, suite)
	ctx, err := NewTLS12CBCContext(keys, suite, TLS12CBCRecordModeEncryptThenMAC)
	if err != nil {
		t.Fatal(err)
	}
	state := ctx.ExportReadState()
	if !bytes.Equal(state.ReadKey, keys.ServerKey) || !bytes.Equal(state.ReadMACKey, keys.ServerMACKey) {
		t.Fatal("exported state does not contain server-read keys")
	}
	if bytes.Equal(state.ReadKey, keys.ClientKey) || bytes.Equal(state.ReadMACKey, keys.ClientMACKey) {
		t.Fatal("exported state contains client-write key material")
	}
	state.ReadKey[0] ^= 1
	if bytes.Equal(state.ReadKey, ctx.readKey) {
		t.Fatal("exported state aliases context memory")
	}
}

func TestTLS12CBCDestroyClearsRecordState(t *testing.T) {
	var suite uint16 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	ctx, err := NewTLS12CBCContext(testTLS12CBCKeys(t, suite), suite, TLS12CBCRecordModeMACThenEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Destroy()
	state := ctx.ExportReadState()
	if len(state.ReadKey) != 0 || len(state.ReadMACKey) != 0 || len(state.ReadIV) != 0 || state.CipherSuite != 0 {
		t.Fatalf("destroyed CBC state remains available: %+v", state)
	}
	if _, err := ctx.EncryptRecord(recordTypeApplicationData, []byte("data")); err == nil {
		t.Fatal("destroyed CBC context accepted a record")
	}
}

func TestTLS12CBCDestroyIsConcurrentSafe(t *testing.T) {
	const suite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	ctx, err := NewTLS12CBCContext(testTLS12CBCKeys(t, suite), suite, TLS12CBCRecordModeMACThenEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			if _, err := ctx.EncryptRecord(recordTypeApplicationData, []byte("request")); err != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			_ = ctx.ExportReadState()
		}
	}()
	close(start)
	ctx.Destroy()
	workers.Wait()

	if _, err := ctx.EncryptRecord(recordTypeApplicationData, []byte("request")); err == nil {
		t.Fatal("destroyed CBC context accepted encryption")
	}
}

func TestTLS12CBCRejectsSHA1WithoutConstantTimeHash(t *testing.T) {
	previous := newTLS12CBCSHA1
	newTLS12CBCSHA1 = func() hash.Hash { return &hashWithoutConstantTimeSum{Hash: sha1.New()} }
	t.Cleanup(func() { newTLS12CBCSHA1 = previous })

	const suite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	if _, err := NewTLS12CBCContext(testTLS12CBCKeys(t, suite), suite, TLS12CBCRecordModeMACThenEncrypt); err == nil || !strings.Contains(err.Error(), "constant-time") {
		t.Fatalf("non-constant-time SHA-1 result: %v", err)
	}
}

func TestTLS12CBCSequenceOverflow(t *testing.T) {
	var suite uint16 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	keys := testTLS12CBCKeys(t, suite)
	ctx, err := NewTLS12CBCContext(keys, suite, TLS12CBCRecordModeMACThenEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	ctx.writeSeq = math.MaxUint64
	if _, err := ctx.EncryptRecord(recordTypeApplicationData, nil); !errors.Is(err, ErrSequenceNumberOverflow) {
		t.Fatalf("write error = %v", err)
	}
	ctx.readSeq = math.MaxUint64
	if _, err := ctx.DecryptRecord(make([]byte, 5), nil); !errors.Is(err, ErrSequenceNumberOverflow) {
		t.Fatalf("read error = %v", err)
	}
}

func TestTLS12CBCKeyBlockLayout(t *testing.T) {
	var suite uint16 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	clientRandom := bytes.Repeat([]byte{1}, 32)
	serverRandom := bytes.Repeat([]byte{2}, 32)
	ks := NewTLS12KeySchedule(suite, bytes.Repeat([]byte{3}, 48), clientRandom, serverRandom)
	keys, err := ks.DeriveCBCKeys()
	if err != nil {
		t.Fatal(err)
	}
	info := GetCipherSuiteInfo(suite)
	want := ks.DeriveKeyBlock(2 * (info.MACSize + info.KeySize + info.IVSize))
	got := make([]byte, 0, len(want))
	got = append(got, keys.ClientMACKey...)
	got = append(got, keys.ServerMACKey...)
	got = append(got, keys.ClientKey...)
	got = append(got, keys.ServerKey...)
	got = append(got, keys.ClientIV...)
	got = append(got, keys.ServerIV...)
	if !bytes.Equal(got, want) {
		t.Fatal("CBC key block fields are out of order")
	}
}

func TestTLS12CBCCipherSuiteConfiguration(t *testing.T) {
	legacyDefault := (&Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS12}).cipherSuites()
	withoutCBC := defaultCipherSuites(VersionTLS12)
	if !slices.Equal(legacyDefault, withoutCBC) {
		t.Fatalf("pre-CBC default suites changed: got %#v, want %#v", legacyDefault, withoutCBC)
	}
	withCBC := (&Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS12, EnableTLS12CBC: true}).cipherSuites()
	wantCBC := []uint16{
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
	if len(withCBC) != len(withoutCBC)+len(wantCBC) {
		t.Fatalf("suite count = %d, want %d", len(withCBC), len(withoutCBC)+len(wantCBC))
	}
	if !slices.Equal(withCBC[len(withoutCBC):], wantCBC) {
		t.Fatalf("CBC preference tail = %#v, want %#v", withCBC[len(withoutCBC):], wantCBC)
	}
	for _, suite := range wantCBC {
		info := GetCipherSuiteInfo(suite)
		if info == nil || !info.IsCBC {
			t.Fatalf("missing suite metadata for 0x%04x", suite)
		}
		parsed, err := ParseCipherSuite(info.Name)
		if err != nil || parsed != suite {
			t.Fatalf("parse %s = 0x%04x, %v", info.Name, parsed, err)
		}
	}
}

func TestTLS12CBCSuiteMetadata(t *testing.T) {
	tests := []struct {
		suite       uint16
		keySize     int
		macSize     int
		macHash     string
		prfHash     string
		keyExchange TLS12KeyExchange
		auth        TLS12Authentication
	}{
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, "SHA1", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, "SHA1", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, "SHA1", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, "SHA1", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA},
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, "SHA256", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, "SHA256", "SHA256", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, "SHA384", "SHA384", TLS12KeyExchangeECDHE, TLS12AuthenticationECDSA},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, "SHA384", "SHA384", TLS12KeyExchangeECDHE, TLS12AuthenticationRSA},
		{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, "SHA1", "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA},
		{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, "SHA1", "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, "SHA256", "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA},
		{TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, "SHA256", "SHA256", TLS12KeyExchangeRSA, TLS12AuthenticationRSA},
	}
	if len(tests) != len(tls12CBCCipherSuites()) {
		t.Fatalf("metadata cases = %d, advertised CBC suites = %d", len(tests), len(tls12CBCCipherSuites()))
	}
	for _, tt := range tests {
		info := GetCipherSuiteInfo(tt.suite)
		if info == nil {
			t.Fatalf("suite 0x%04x has no metadata", tt.suite)
		}
		if info.KeySize != tt.keySize || info.MACSize != tt.macSize || info.MACHash != tt.macHash || info.HashFunc != tt.prfHash || info.KeyExchange != tt.keyExchange || info.Authentication != tt.auth {
			t.Fatalf("suite %s metadata = %+v", info.Name, info)
		}
	}
}

func TestTLS12CBCSHA384PRF(t *testing.T) {
	secret := []byte("secret")
	seed := []byte("seed")
	label := "test label"
	want := pHash(sha512.New384, secret, append([]byte(label), seed...), 64)
	for _, suite := range []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	} {
		if got := prf12(suite, secret, label, seed, 64); !bytes.Equal(got, want) {
			t.Fatalf("suite 0x%04x used the wrong TLS 1.2 PRF", suite)
		}
	}
}

func TestTLS12CBCHandshakeInteroperability(t *testing.T) {
	rsaCertificate, rsaRootPool := testTLSCertificate(t, "cbc.test")
	ecdsaCertificate, ecdsaRootPool := testTLSECDSACertificate(t, "cbc.test")
	t.Cleanup(func() { shared.SetRootCAPool(nil) })

	tests := []struct {
		suite       uint16
		certificate tls.Certificate
		rootPool    *x509.CertPool
	}{
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, ecdsaCertificate, ecdsaRootPool},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, rsaCertificate, rsaRootPool},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, ecdsaCertificate, ecdsaRootPool},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, rsaCertificate, rsaRootPool},
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ecdsaCertificate, ecdsaRootPool},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, rsaCertificate, rsaRootPool},
		{TLS_RSA_WITH_AES_128_CBC_SHA, rsaCertificate, rsaRootPool},
		{TLS_RSA_WITH_AES_256_CBC_SHA, rsaCertificate, rsaRootPool},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, rsaCertificate, rsaRootPool},
	}
	for _, test := range tests {
		suite := test.suite
		shared.SetRootCAPool(test.rootPool)
		t.Run(GetCipherSuiteInfo(suite).Name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			deadline := time.Now().Add(5 * time.Second)
			if err := clientConn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := serverConn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			serverErrors := make(chan error, 1)
			go func() {
				server := tls.Server(serverConn, &tls.Config{
					Certificates:           []tls.Certificate{test.certificate},
					MinVersion:             tls.VersionTLS12,
					MaxVersion:             tls.VersionTLS12,
					CipherSuites:           []uint16{suite},
					SessionTicketsDisabled: true,
				})
				if err := server.Handshake(); err != nil {
					serverErrors <- err
					return
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(server, request); err != nil {
					serverErrors <- err
					return
				}
				if !bytes.Equal(request, []byte("ping")) {
					serverErrors <- errors.New("server received wrong CBC application plaintext")
					return
				}
				_, err := server.Write([]byte("pong"))
				serverErrors <- err
			}()

			client := NewClientWithConfig(clientConn, &Config{
				MinVersion:   VersionTLS12,
				MaxVersion:   VersionTLS12,
				CipherSuites: []uint16{suite},
			})
			if err := client.Handshake("cbc.test"); err != nil {
				t.Fatalf("CBC handshake: %v", err)
			}
			if client.GetTLS12CBC() == nil || client.GetTLS12AEAD() != nil {
				t.Fatal("CBC handshake initialized the wrong record context")
			}
			if client.TLS12EncryptThenMAC() {
				t.Fatal("crypto/tls server unexpectedly negotiated Encrypt-then-MAC")
			}
			if !client.TLS12ExtendedMasterSecret() {
				t.Fatal("crypto/tls server did not negotiate Extended Master Secret")
			}

			requestRecord, err := client.GetTLS12CBC().EncryptRecord(recordTypeApplicationData, []byte("ping"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clientConn.Write(requestRecord); err != nil {
				t.Fatal(err)
			}
			header := make([]byte, 5)
			if _, err := io.ReadFull(clientConn, header); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, int(header[3])<<8|int(header[4]))
			if _, err := io.ReadFull(clientConn, payload); err != nil {
				t.Fatal(err)
			}
			response, err := client.GetTLS12CBC().DecryptRecord(header, payload)
			if err != nil {
				t.Fatalf("decrypt server CBC application record: %v", err)
			}
			if !bytes.Equal(response, []byte("pong")) {
				t.Fatalf("response = %q", response)
			}
			if err := <-serverErrors; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestTLS12CertificateKeyUsageMatchesKeyExchange(t *testing.T) {
	const dnsName = "cbc-key-usage.test"
	newRSACertificate := func(keyUsage x509.KeyUsage) (tls.Certificate, *x509.CertPool) {
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return testTLSCertificateWithLeafKey(t, dnsName, leafKey, keyUsage)
	}
	enciphermentCert, enciphermentRoots := newRSACertificate(x509.KeyUsageKeyEncipherment)
	signingCert, signingRoots := newRSACertificate(x509.KeyUsageDigitalSignature)
	t.Cleanup(func() { shared.SetRootCAPool(nil) })

	tests := []struct {
		name    string
		suite   uint16
		cert    tls.Certificate
		roots   *x509.CertPool
		wantErr bool
	}{
		{name: "static RSA accepts key encipherment", suite: TLS_RSA_WITH_AES_128_CBC_SHA, cert: enciphermentCert, roots: enciphermentRoots},
		{name: "static RSA rejects signing only", suite: TLS_RSA_WITH_AES_128_CBC_SHA, cert: signingCert, roots: signingRoots, wantErr: true},
		{name: "ECDHE RSA accepts signing", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, cert: signingCert, roots: signingRoots},
		{name: "ECDHE RSA rejects encipherment only", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, cert: enciphermentCert, roots: enciphermentRoots, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shared.SetRootCAPool(tt.roots)
			certificates := make([]*x509.Certificate, 0, len(tt.cert.Certificate))
			for _, der := range tt.cert.Certificate {
				certificate, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				certificates = append(certificates, certificate)
			}
			client := NewClientWithConfig(nil, &Config{})
			client.cipherSuite = tt.suite
			err := client.verifyCertificateChain(certificates, dnsName, client.Config)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyCertificateChain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLS12CipherSuiteAuthenticationFamily(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaCertificate := &x509.Certificate{PublicKey: &rsaKey.PublicKey}
	ecdsaCertificate := &x509.Certificate{PublicKey: &ecdsaKey.PublicKey}

	certificateTests := []struct {
		name        string
		suite       uint16
		certificate *x509.Certificate
		wantErr     bool
	}{
		{name: "ECDHE RSA with RSA certificate", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, certificate: rsaCertificate},
		{name: "ECDHE RSA with ECDSA certificate", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, certificate: ecdsaCertificate, wantErr: true},
		{name: "ECDHE ECDSA with ECDSA certificate", suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, certificate: ecdsaCertificate},
		{name: "ECDHE ECDSA with RSA certificate", suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, certificate: rsaCertificate, wantErr: true},
		{name: "static RSA with RSA certificate", suite: TLS_RSA_WITH_AES_128_CBC_SHA, certificate: rsaCertificate},
		{name: "static RSA with ECDSA certificate", suite: TLS_RSA_WITH_AES_128_CBC_SHA, certificate: ecdsaCertificate, wantErr: true},
	}
	for _, tt := range certificateTests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClientWithConfig(nil, &Config{})
			client.cipherSuite = tt.suite
			err := client.validateTLS12CertificateAuthentication(tt.certificate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("certificate authentication error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	signatureTests := []struct {
		name      string
		suite     uint16
		cert      *x509.Certificate
		signature uint16
	}{
		{name: "RSA suite rejects ECDSA signature", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, cert: rsaCertificate, signature: ecdsa_secp256r1_sha256},
		{name: "ECDSA suite rejects RSA signature", suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, cert: ecdsaCertificate, signature: rsa_pkcs1_sha256},
	}
	for _, tt := range signatureTests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClientWithConfig(nil, &Config{})
			client.cipherSuite = tt.suite
			client.serverCertificates = []*x509.Certificate{tt.cert}
			err := client.verifyServerKeyExchangeSignature(&ServerKeyExchangeMsg{signAlg: tt.signature})
			if err == nil || !strings.Contains(err.Error(), "authenticated cipher suite received") {
				t.Fatalf("signature-family mismatch result: %v", err)
			}
		})
	}
}

func testTLSCertificate(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testTLSCertificateWithLeafKey(t, dnsName, leafKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
}

func testTLSECDSACertificate(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testTLSCertificateWithLeafKey(t, dnsName, leafKey, x509.KeyUsageDigitalSignature)
}

func testTLSCertificateWithLeafKey(t *testing.T, dnsName string, leafKey crypto.Signer, keyUsage x509.KeyUsage) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CBC test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER},
		PrivateKey:  leafKey,
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	return certificate, rootPool
}
