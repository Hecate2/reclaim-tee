//go:build !mobile

package shared

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretspb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type gcpSecretManagerInner struct {
	client *secretmanager.Client
}

func NewGCPSecretManagerInner() (GCPSecretManagerInner, error) {
	ctx := context.Background()
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %v", err)
	}
	return &gcpSecretManagerInner{client: c}, nil
}

func (g *gcpSecretManagerInner) CreateIfNotExists(ctx context.Context, projectID, secretID string) error {
	// Attempt to create secret; ignore already exists errors
	_, err := g.client.CreateSecret(ctx, &secretspb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", projectID),
		SecretId: secretID,
		Secret: &secretspb.Secret{
			Replication: &secretspb.Replication{Replication: &secretspb.Replication_Automatic_{}},
		},
	})
	if err != nil {
		// Best-effort: proceed; AccessLatest/AddVersion will fail if truly missing
		return nil
	}
	return nil
}

func (g *gcpSecretManagerInner) AddVersion(ctx context.Context, projectID, secretID string, payload []byte) error {
	_, err := g.client.AddSecretVersion(ctx, &secretspb.AddSecretVersionRequest{
		Parent:  fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID),
		Payload: &secretspb.SecretPayload{Data: payload},
	})
	return err
}

func (g *gcpSecretManagerInner) AccessLatest(ctx context.Context, projectID, secretID string) ([]byte, error) {
	resp, err := g.client.AccessSecretVersion(ctx, &secretspb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID),
	})
	if err != nil {
		return nil, err
	}
	return resp.Payload.GetData(), nil
}
