package client

import (
	"crypto/tls"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

// newRATLSWebSocketDialer builds a WebSocket dialer wired for RA-TLS.
// The TEE's self-signed cert can't be verified through the usual CA
// chain (InsecureSkipVerify), so VerifyPeerCertificate runs the
// attestation check instead. For Secure Boot certificates, updated clients
// prefer the additive proof and verify the release key R before sending
// application data. Old clients use the retained legacy SNP extension. The
// client does not pin app identity; the attestor returns it to the external
// verifier as before.
//
// peerRole is "tee_k" or "tee_t" — picks the right SPKI nonce prefix
// for the binding check.
func newRATLSWebSocketDialer(peerRole string, logger *shared.Logger) *websocket.Dialer {
	return &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			// RA-TLS certs are self-signed; the attestation extension is
			// the proof, not a CA-issued cert.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: shared.VerifyRATLSAttestation(peerRole, logger),
			// TLS 1.3 only — both ends are our Go binaries, no legacy
			// compatibility constraint. Independent of minitls's
			// separate target-server handshake.
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
	}
}
