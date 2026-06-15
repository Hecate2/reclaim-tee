package signer

import "github.com/golang-jwt/jwt/v5"

// AllocClaims are the claims embedded in a router-minted allocation JWT.
// Reads from the spec: iss/aud/iat/exp/jti via RegisteredClaims, plus
// pair-specific addresses and client-supplied nonce.
type AllocClaims struct {
	TEEKAddr    string `json:"teek_addr"`
	TEETAddr    string `json:"teet_addr"`
	ClientNonce string `json:"client_nonce"`
	jwt.RegisteredClaims
}
