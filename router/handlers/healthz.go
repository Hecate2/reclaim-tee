package handlers

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
)

// HandleHealthz answers Cloud Run / load balancer liveness probes. Returns
// HTTP 200 with a JSON body exposing whether the router is running in
// standalone mode — deploy-verification scripts should assert
// standalone=false before flipping production traffic.
func (s *Server) HandleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.MarshalEncode(jsontext.NewEncoder(w), struct {
		Status     string `json:"status"`
		Standalone bool   `json:"standalone"`
	}{
		Status:     "ok",
		Standalone: s.Config.Standalone,
	})
}
