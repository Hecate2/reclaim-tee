package main

import (
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetEnvReplacesEveryUntrustedCopy(t *testing.T) {
	env := []string{"A=1", "SNP_APP_HASH=metadata", "B=2", "SNP_APP_HASH=duplicate"}
	got := setEnv(env, "SNP_APP_HASH", "measured")
	want := []string{"A=1", "B=2", "SNP_APP_HASH=measured"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setEnv = %#v, want %#v", got, want)
	}
}

func TestSelectedEnvGivesBrokerNoDeploymentSecrets(t *testing.T) {
	env := []string{
		"SSL_CERT_FILE=/run/bundle/ca.pem",
		"HTTPS_PROXY=http://proxy",
		"KMS_ENCLAVE_DOMAIN_KEY=secret",
		"JWT_PRIVATE_KEY=secret",
	}
	got := selectedEnv(env, "SSL_CERT_FILE", "HTTPS_PROXY")
	want := []string{"SSL_CERT_FILE=/run/bundle/ca.pem", "HTTPS_PROXY=http://proxy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectedEnv = %#v, want %#v", got, want)
	}
}

func TestAWSAppRunsUnprivilegedWithOnlyBindCapability(t *testing.T) {
	attr := awsAppSysProcAttr()
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig = %v, want SIGKILL", attr.Pdeathsig)
	}
	if attr.Credential == nil || attr.Credential.Uid != snpAppUID || attr.Credential.Gid != snpAppUID || !attr.Credential.NoSetGroups {
		t.Fatalf("credential = %#v", attr.Credential)
	}
	want := []uintptr{unix.CAP_NET_BIND_SERVICE}
	if !reflect.DeepEqual(attr.AmbientCaps, want) {
		t.Fatalf("AmbientCaps = %#v, want %#v", attr.AmbientCaps, want)
	}
}
