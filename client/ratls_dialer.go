package client

import (
	"crypto/tls"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

// newRATLSWebSocketDialer builds a WebSocket dialer wired for RA-TLS.
// The TEE's self-signed cert can't be verified through the usual CA
// chain (InsecureSkipVerify), so VerifyPeerCertificate runs the
// attestation check instead: confirms the GCP attestation JWT is signed
// by Google and that the SPKI nonce inside the JWT binds to the cert's
// actual public key. Does NOT pin image_digest — the TEEs embed their
// full attestation reports into the signed claim bundles the attestor
// inspects downstream, so the client doesn't need to look at what's
// inside the attestation.
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
