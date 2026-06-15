package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

// TestASN1ToJWS_RoundTrip generates a fresh ECDSA signature, runs it through
// the ASN.1->raw converter, and verifies the raw form decodes back to the
// same (r, s) pair the signer produced.
func TestASN1ToJWS_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	digest := sha256.Sum256([]byte("test message"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Emulate KMS by encoding r, s as ASN.1 DER.
	derSig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal der: %v", err)
	}

	raw, err := asn1ToJWS(derSig)
	if err != nil {
		t.Fatalf("asn1ToJWS: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("expected 64-byte raw signature, got %d", len(raw))
	}

	// Decode r and s back out of the raw form and confirm they match.
	gotR := new(big.Int).SetBytes(raw[:32])
	gotS := new(big.Int).SetBytes(raw[32:])
	if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
		t.Fatalf("round trip mismatch:\n  want r=%s s=%s\n  got  r=%s s=%s",
			r.String(), s.String(), gotR.String(), gotS.String())
	}

	// Sanity: the raw signature must verify against the original public key.
	if !ecdsa.Verify(&priv.PublicKey, digest[:], gotR, gotS) {
		t.Fatal("decoded signature failed ECDSA verify")
	}
}

// TestASN1ToJWS_PadsLeadingZeros handles the case where r or s decodes to a
// big.Int whose .Bytes() representation is shorter than 32 bytes (high bytes
// were zero). The raw JWS form must left-pad with zeros.
func TestASN1ToJWS_PadsLeadingZeros(t *testing.T) {
	// Hand-construct r and s that are 30 bytes each so they need padding.
	r := new(big.Int).SetBytes(make([]byte, 30))
	r.SetBit(r, 0, 1) // r = 1
	s := new(big.Int).Lsh(big.NewInt(1), 8*29)

	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal der: %v", err)
	}

	raw, err := asn1ToJWS(der)
	if err != nil {
		t.Fatalf("asn1ToJWS: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("expected 64-byte raw signature, got %d", len(raw))
	}
	// r = 1 → last byte of first 32 should be 0x01, all others zero.
	for i := range 31 {
		if raw[i] != 0 {
			t.Fatalf("expected zero at raw[%d], got %#x", i, raw[i])
		}
	}
	if raw[31] != 0x01 {
		t.Fatalf("expected raw[31]=0x01, got %#x", raw[31])
	}
}

func TestASN1ToJWS_RejectsMalformedInput(t *testing.T) {
	if _, err := asn1ToJWS([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatal("expected error on malformed DER input")
	}
}
