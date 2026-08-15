package minitls

import (
	"os"
	"strings"
	"testing"
)

func TestTLS12SecretsAreNotLogged(t *testing.T) {
	source, err := os.ReadFile("client12.go")
	if err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range []string{
		`fmt.Sprintf("%x", sharedSecret)`,
		`fmt.Sprintf("%x", c.tls12KeySchedule.masterSecret)`,
		`zap.String("secret",`,
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("TLS secret is passed to logging: %s", forbidden)
		}
	}
}
