package handlers

import (
	"net/http"

	"go.uber.org/zap"
)

// HandleJWTPubKey returns the router's allocation-JWT verification key in
// PEM (SPKI) form. TEEs and clients can fetch this at boot instead of
// being statically configured with it — useful for local-dev demos where
// the standalone signer generates a fresh keypair each run.
func (s *Server) HandleJWTPubKey(w http.ResponseWriter, _ *http.Request) {
	pem, err := s.Signer.PublicKeyPEM()
	if err != nil {
		s.Logger.Error("jwt-pubkey: extract failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem)
}
