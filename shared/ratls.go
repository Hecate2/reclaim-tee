//go:build !mobile

package shared

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"sync/atomic"
	"time"
)

// X.509 extension OID for the embedded GCP Confidential Space attestation JWT.
// Reclaim PEN = 65998; .1 reserved for the attestation extension.
var AttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65998, 1}

// AttestationOIDSEVSNP carries a marshaled go-sev-guest Attestation (raw
// SEV-SNP report + VCEK/ASK/ARK chain) for TEEs running on a plain SEV-SNP
// Confidential VM. Separate OID from .1 so verifiers dispatch on which
// extension is present and deployed Confidential Space certs (.1 only) keep
// verifying unchanged.
var AttestationOIDSEVSNP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65998, 2}

// launcherSocketPath is where the Confidential Space launcher exposes its
// attestation API. Its presence is how we tell "running in an enclave" apart
// from "running locally for dev." Kept in sync with shared/gcp_attestation.go.
const launcherSocketPath = "/run/container_launcher/teeserver.sock"

// SPKINoncePrefix returns the eat_nonce prefix used to bind the TLS public
// key hash into the attestation report. role is "tee_k" or "tee_t".
func SPKINoncePrefix(role string) string {
	return role + "_spki_hash:"
}

// SPKIHashFromCertDER parses the given DER-encoded X.509 certificate and
// returns sha256(MarshalPKIXPublicKey(cert.PublicKey)) — the value the
// SPKI nonce in an RA-TLS attestation binds to. This MUST be computed
// identically on all peers, so the implementation lives in one place.
//
// Used by:
//   - The TEEs when building the SPKI nonce for their per-session
//     attestation (binding the signed bundle to the TLS keypair, which
//     is invariant across cert refreshes).
//   - The TEEs when verifying the peer's per-session attestation against
//     the peer's TLS cert.
//   - The client when verifying TEE_K/TEE_T's per-session attestation
//     against the cert it saw on its WS connection.
func SPKIHashFromCertDER(certDER []byte) ([32]byte, error) {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse cert: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal SPKI: %w", err)
	}
	return sha256.Sum256(spkiDER), nil
}

// RATLSManager owns an ephemeral ECDSA P-256 keypair and a self-signed
// X.509 certificate that embeds a GCP attestation report as an extension.
//
// The keypair is generated once at NewRATLSManager and never rotated; the
// SPKI hash that the attestation binds to is therefore stable for the
// lifetime of the manager. The cert + its embedded attestation, however,
// must be rotated periodically — GCP attestations have a TTL of ~5 minutes,
// after which new TLS handshakes verifying via `VerifyRATLSPeer` will fail
// the `exp` check on the embedded JWT. Callers should arrange to call
// Refresh on a ticker (e.g. every 4 minutes, matching the existing
// per-TEE attestation refresh cadence).
//
// All accessors are safe for concurrent use; Refresh atomically swaps the
// cert without disrupting in-flight handshakes (Go's TLS stack reads
// GetCertificate per-handshake, so existing sessions are unaffected).
type RATLSManager struct {
	role        string
	extraNonces []string
	priv        *ecdsa.PrivateKey
	spkiHash    [32]byte
	cert        atomic.Pointer[tls.Certificate]
}

// NewRATLSManager generates a fresh keypair and builds the initial cert.
// Returns an error if the launcher socket exists (i.e. we're in an enclave)
// and the attestation request fails — a launcher failure in enclave mode
// is a real production issue and we must not silently mask it as
// standalone-dev mode.
func NewRATLSManager(ctx context.Context, role string, extraNonces []string) (*RATLSManager, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal SPKI: %w", err)
	}
	m := &RATLSManager{
		role:        role,
		extraNonces: extraNonces,
		priv:        priv,
		spkiHash:    sha256.Sum256(spkiDER),
	}
	if err := m.Refresh(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Refresh requests a new attestation, builds a new cert with the same
// keypair plus the fresh attestation, and atomically swaps it in. Existing
// TLS sessions continue to use whatever cert was active at handshake time;
// new handshakes pick up the new cert via GetCertificate.
//
// In standalone (non-enclave) mode — detected by the absence of the
// Confidential Space launcher socket — Refresh produces a cert without
// the attestation extension. Peers verifying via VerifyRATLSPeer will
// reject such certs; standalone-mode TEE↔TEE comms must use a different
// TLS verifier path.
func (m *RATLSManager) Refresh(ctx context.Context) error {
	extraExts, err := m.acquireAttestationExts(ctx)
	if err != nil {
		return fmt.Errorf("ratls refresh: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("ratls refresh: random serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: m.role},
		// Cert time bounds are formality only — RA-TLS verification doesn't
		// check them. Set a 1-day window so any consumer doing strict checks
		// catches stale certs and prompts a Refresh.
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extraExts,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &m.priv.PublicKey, m.priv)
	if err != nil {
		return fmt.Errorf("ratls refresh: create cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(derCert)
	if err != nil {
		return fmt.Errorf("ratls refresh: parse just-created cert: %w", err)
	}

	m.cert.Store(&tls.Certificate{
		Certificate: [][]byte{derCert},
		PrivateKey:  m.priv,
		Leaf:        leaf,
	})
	return nil
}

// Certificate returns the currently-active certificate. Mostly used by tests
// and admin endpoints; live TLS configs should use GetCertificate so they
// automatically pick up Refresh()es.
func (m *RATLSManager) Certificate() *tls.Certificate {
	return m.cert.Load()
}

// CertificateRaw returns the DER-encoded leaf of the currently-active cert.
// API-compatible with the LegoManager.GetCertificateRaw() shape it replaces.
func (m *RATLSManager) CertificateRaw() []byte {
	c := m.cert.Load()
	if c == nil {
		return nil
	}
	return c.Certificate[0]
}

// SPKIHash returns sha256(SPKI) of the TLS keypair. Stable for the lifetime
// of the manager (key never rotates).
func (m *RATLSManager) SPKIHash() [32]byte {
	return m.spkiHash
}

// PublicKeyDER returns the PKIX-marshaled RA-TLS public key. Its sha256 is
// what the attestation's SPKI nonce commits to, so a verifier can recover
// and trust the registration-signing key from the attestation alone.
func (m *RATLSManager) PublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&m.priv.PublicKey)
}

// SignRegistration signs a registration digest with the RA-TLS private key
// (ECDSA P-256, ASN.1 form). The key never leaves the enclave.
func (m *RATLSManager) SignRegistration(digest [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, m.priv, digest[:])
}

// GetCertificate is intended for tls.Config.GetCertificate. Always returns
// the current cert, so handshakes that arrive after a Refresh() see the
// fresh attestation.
func (m *RATLSManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := m.cert.Load()
	if c == nil {
		return nil, errors.New("ratls: no cert available (Refresh never succeeded)")
	}
	return c, nil
}

// GetClientCertificate is intended for tls.Config.GetClientCertificate when
// the TEE acts as TLS client and the peer requires client certs (mTLS).
func (m *RATLSManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.GetCertificate(nil)
}

// ServerTLSConfig returns a base tls.Config suitable for a TEE acting as a
// TLS server. It installs GetCertificate so refreshes are picked up, but
// does NOT set ClientAuth or VerifyPeerCertificate — callers wiring up
// mTLS for TEE↔TEE links must add those themselves with a verifier built
// from `VerifyRATLSPeer`.
func (m *RATLSManager) ServerTLSConfig() *tls.Config {
	// TLS 1.3 only on the RA-TLS layer (TEE↔TEE peer link, client↔TEE).
	// This is independent of the protocol's separate TLS-to-target
	// handshake handled by minitls, which must keep 1.2 support.
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
	}
}

// IsEnclaveMode reports whether the process appears to be running inside a
// GCP Confidential Space launcher (the attestation socket is present).
// Useful for callers that need to take different code paths in dev vs prod
// — but production code paths should be the default; reach for this only
// when local-dev parity is genuinely required.
func IsEnclaveMode() bool {
	_, err := os.Stat(launcherSocketPath)
	return err == nil
}

// IsProductionTEE reports whether this TEE runs in a real attested environment
// — Confidential Space (launcher socket) or SEV-SNP (/dev/sev-guest) — versus
// local dev. Both take the RA-TLS + attested-registration path.
func IsProductionTEE() bool {
	return IsEnclaveMode() || IsSEVSNPMode()
}

// acquireAttestationExts builds the attestation cert extension(s) for the
// current platform, dispatching on how this TEE is deployed:
//
//   - Confidential Space (launcher socket present): emit a CS-JWT under
//     AttestationOID. This is the deployed v2 path and takes priority.
//   - Plain SEV-SNP CVM (/dev/sev-guest present): emit a marshaled SEV-SNP
//     report under AttestationOIDSEVSNP, with report_data binding the SPKI
//     hash and the self binary hash.
//   - Standalone dev (neither present): no extension. Peers using
//     VerifyRATLSPeer will reject such certs; standalone TEE↔TEE comms must
//     use a different verifier path.
//
// A launcher-socket-present call that fails is a real production bug and is
// surfaced as an error rather than silently degrading to standalone mode.
func (m *RATLSManager) acquireAttestationExts(ctx context.Context) ([]pkix.Extension, error) {
	if _, err := os.Stat(launcherSocketPath); !errors.Is(err, fs.ErrNotExist) {
		spkiNonce := SPKINoncePrefix(m.role) + hex.EncodeToString(m.spkiHash[:])
		nonces := append([]string{spkiNonce}, m.extraNonces...)
		jwt, err := GenerateGCPAttestation(ctx, nonces...)
		if err != nil {
			return nil, err
		}
		return []pkix.Extension{{Id: AttestationOID, Critical: false, Value: jwt}}, nil
	}

	if IsSEVSNPMode() {
		// Combined attestation: AMD SEV-SNP report + vTPM AK/PCR quotes, with the
		// SEV report_data committing to the vTPM AK and this cert's SPKI. Code
		// identity lives in PCR 8 (app) / PCR 11 (base); the SEV measurement is
		// firmware-only, so the binding to the AK is what makes the PCR quote
		// trustworthy without splicing.
		spkiDER, err := m.PublicKeyDER()
		if err != nil {
			return nil, fmt.Errorf("ra-tls SPKI: %w", err)
		}
		// appHash (= sha256(app bundle)) is measured + exported by the loader; it's
		// the cross-cloud payload identity, proven against PCR 8 by the verifier.
		appHash, herr := hex.DecodeString(os.Getenv("SNP_APP_HASH"))
		if herr != nil || len(appHash) == 0 {
			return nil, fmt.Errorf("SNP_APP_HASH not set by loader")
		}
		var att []byte
		tag := byte(snpAttestTagGCP)
		if IsAWSSEVSNP() {
			tag = snpAttestTagAWS
			att, err = GenerateCombinedAWSAttestation(spkiDER, appHash)
		} else {
			att, err = GenerateCombinedGCPAttestation(spkiDER, appHash)
		}
		if err != nil {
			return nil, err
		}
		// Tag the payload so the verifier dispatches to the right per-cloud path.
		return []pkix.Extension{{Id: AttestationOIDSEVSNP, Critical: false, Value: append([]byte{tag}, att...)}}, nil
	}

	return nil, nil
}
