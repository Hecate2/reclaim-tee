package minitls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestTLS12RSAGCMSuiteMetadata(t *testing.T) {
	tests := []struct {
		suite   uint16
		id      uint16
		name    string
		hex     string
		keySize int
		hash    string
	}{
		{TLS_RSA_WITH_AES_128_GCM_SHA256, 0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", "0x009c", 16, "SHA256"},
		{TLS_RSA_WITH_AES_256_GCM_SHA384, 0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384", "0x009d", 32, "SHA384"},
	}

	for _, tt := range tests {
		if tt.suite != tt.id {
			t.Fatalf("%s = 0x%04x, want 0x%04x", tt.name, tt.suite, tt.id)
		}
		info := GetCipherSuiteInfo(tt.suite)
		if info == nil {
			t.Fatalf("suite 0x%04x has no metadata", tt.suite)
		}
		if info.Name != tt.name || info.KeySize != tt.keySize || info.HashFunc != tt.hash ||
			info.IsTLS13 || info.IsCBC || info.KeyExchange != TLS12KeyExchangeRSA ||
			info.Authentication != TLS12AuthenticationRSA || !IsTLS12AESGCMCipherSuite(tt.suite) {
			t.Fatalf("suite %s metadata = %+v", tt.name, info)
		}
		for _, value := range []string{tt.name, tt.hex} {
			parsed, err := ParseCipherSuite(value)
			if err != nil || parsed != tt.suite {
				t.Fatalf("ParseCipherSuite(%q) = 0x%04x, %v", value, parsed, err)
			}
		}
	}
}

func TestTLS12RSAGCMAEAD(t *testing.T) {
	tests := []struct {
		name    string
		suite   uint16
		keySize int
	}{
		{"AES-128-GCM", TLS_RSA_WITH_AES_128_GCM_SHA256, 16},
		{"AES-256-GCM", TLS_RSA_WITH_AES_256_GCM_SHA384, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientKey := bytes.Repeat([]byte{1}, tt.keySize)
			serverKey := bytes.Repeat([]byte{2}, tt.keySize)
			clientIV := []byte{3, 4, 5, 6}
			serverIV := []byte{7, 8, 9, 10}
			client, err := NewTLS12AEADContext(clientKey, clientIV, serverKey, serverIV, tt.suite)
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewTLS12AEADContext(serverKey, serverIV, clientKey, clientIV, tt.suite)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := []byte("static RSA AES-GCM")
			header := []byte{recordTypeApplicationData, 0x03, 0x03, 0, byte(len(plaintext))}
			ciphertext, err := client.Encrypt(plaintext, header)
			if err != nil {
				t.Fatal(err)
			}
			split := NewSplitAEAD(clientKey, clientIV, tt.suite)
			splitAAD := CreateAdditionalDataTLS12(0, len(plaintext))
			splitCiphertext, tagSecrets, err := split.EncryptWithoutTag(plaintext, splitAAD)
			if err != nil {
				t.Fatal(err)
			}
			splitTag, err := ComputeTagFromSecrets(splitCiphertext, tagSecrets, tt.suite, splitAAD)
			if err != nil {
				t.Fatal(err)
			}
			if splitPayload := CreateAEADPayload(tt.suite, 0, splitCiphertext, splitTag); !bytes.Equal(splitPayload, ciphertext) {
				t.Fatalf("split AEAD payload does not match standard TLS 1.2 AES-GCM payload")
			}
			keystream, _, err := GenerateDecryptionStreamWithNonce(
				clientKey, clientIV, 0, len(plaintext), tt.suite, ciphertext[:8],
			)
			if err != nil {
				t.Fatal(err)
			}
			reconstructed := make([]byte, len(plaintext))
			for i := range reconstructed {
				reconstructed[i] = ciphertext[8+i] ^ keystream[i]
			}
			if !bytes.Equal(reconstructed, plaintext) {
				t.Fatalf("split response reconstruction = %q, want %q", reconstructed, plaintext)
			}
			decrypted, err := server.Decrypt(ciphertext, header)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestTLS12RSAGCMHandshakeInteroperability(t *testing.T) {
	const serverName = "rsa-gcm.test"
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate, roots := testTLSCertificateWithLeafKey(
		t, serverName, leafKey, x509.KeyUsageDigitalSignature,
	)
	t.Cleanup(func() { shared.SetRootCAPool(nil) })

	for _, suite := range []uint16{
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
	} {
		shared.SetRootCAPool(roots)
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
					Certificates:           []tls.Certificate{certificate},
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
					serverErrors <- errors.New("server received wrong RSA-GCM application plaintext")
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
			if err := client.Handshake(serverName); err != nil {
				t.Fatalf("RSA-GCM handshake: %v", err)
			}
			if client.GetCipherSuite() != suite || client.GetTLS12AEAD() == nil || client.GetTLS12CBC() != nil {
				t.Fatal("RSA-GCM handshake initialized the wrong record context")
			}

			request := []byte("ping")
			requestAAD := []byte{recordTypeApplicationData, 0x03, 0x03, 0, byte(len(request))}
			requestPayload, err := client.GetTLS12AEAD().Encrypt(request, requestAAD)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clientConn.Write(CreateTLSRecord(recordTypeApplicationData, requestPayload)); err != nil {
				t.Fatal(err)
			}

			header := make([]byte, 5)
			if _, err := io.ReadFull(clientConn, header); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
			if _, err := io.ReadFull(clientConn, payload); err != nil {
				t.Fatal(err)
			}
			plaintextLength := len(payload) - 8 - 16
			responseAAD := append([]byte(nil), header...)
			binary.BigEndian.PutUint16(responseAAD[3:5], uint16(plaintextLength))
			response, err := client.GetTLS12AEAD().Decrypt(payload, responseAAD)
			if err != nil {
				t.Fatal(err)
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
