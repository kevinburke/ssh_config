package ssh_config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateTestEd25519Key(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

func generateTestRSAKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal rsa private key: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

func TestToClientConfigUser(t *testing.T) {
	configText := `
Host custom-user
	User testdeployer
Host default-user
	Port 22
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	cc, err := cfg.ToClientConfig("custom-user")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if cc.User != "testdeployer" {
		t.Errorf("expected user 'testdeployer', got %q", cc.User)
	}

	ccDefault, err := cfg.ToClientConfig("default-user")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	expectedUser := ""
	if u, err := osuser.Current(); err == nil && u.Username != "" {
		expectedUser = u.Username
	} else if env := os.Getenv("USER"); env != "" {
		expectedUser = env
	}
	if expectedUser != "" && ccDefault.User != expectedUser {
		t.Errorf("expected default user %q, got %q", expectedUser, ccDefault.User)
	}
}

func TestToClientConfigPortAndAddress(t *testing.T) {
	configText := `
Host standard
	Hostname 192.168.1.100
	Port 2222
Host no-port
	Hostname example.org
Host invalid-port
	Port 70000
Host not-a-number
	Port abc
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	port, err := cfg.Port("standard")
	if err != nil {
		t.Fatalf("unexpected port error: %v", err)
	}
	if port != 2222 {
		t.Errorf("expected port 2222, got %d", port)
	}

	addr, err := cfg.Address("standard")
	if err != nil {
		t.Fatalf("unexpected address error: %v", err)
	}
	if addr != "192.168.1.100:2222" {
		t.Errorf("expected address 192.168.1.100:2222, got %q", addr)
	}

	defaultPort, err := cfg.Port("no-port")
	if err != nil {
		t.Fatalf("unexpected port error: %v", err)
	}
	if defaultPort != 22 {
		t.Errorf("expected default port 22, got %d", defaultPort)
	}

	defaultAddr, err := cfg.Address("no-port")
	if err != nil {
		t.Fatalf("unexpected address error: %v", err)
	}
	if defaultAddr != "example.org:22" {
		t.Errorf("expected address example.org:22, got %q", defaultAddr)
	}

	aliasFallbackAddr, err := cfg.Address("unknown-alias")
	if err != nil {
		t.Fatalf("unexpected address error: %v", err)
	}
	if aliasFallbackAddr != "unknown-alias:22" {
		t.Errorf("expected address unknown-alias:22, got %q", aliasFallbackAddr)
	}

	if _, err := cfg.Port("invalid-port"); err == nil {
		t.Errorf("expected error for port 70000, got nil")
	}
	if _, err := cfg.ToClientConfig("invalid-port"); err == nil {
		t.Errorf("expected error for invalid port in ToClientConfig, got nil")
	}

	if _, err := cfg.Port("not-a-number"); err == nil {
		t.Errorf("expected error for non-numeric port, got nil")
	}
	if _, err := cfg.ToClientConfig("not-a-number"); err == nil {
		t.Errorf("expected error for non-numeric port in ToClientConfig, got nil")
	}
}

func TestToClientConfigKeyConversions(t *testing.T) {
	tmpDir := t.TempDir()

	edKeyPEM, _ := generateTestEd25519Key(t)
	edKeyPath := filepath.Join(tmpDir, "id_ed25519")
	if err := os.WriteFile(edKeyPath, []byte(edKeyPEM), 0600); err != nil {
		t.Fatalf("failed to write ed25519 key: %v", err)
	}

	rsaKeyPEM, _ := generateTestRSAKey(t)
	rsaKeyPath := filepath.Join(tmpDir, "id_rsa")
	if err := os.WriteFile(rsaKeyPath, []byte(rsaKeyPEM), 0600); err != nil {
		t.Fatalf("failed to write rsa key: %v", err)
	}

	configText := fmt.Sprintf(`
Host with-file-key
	IdentityFile %s
Host with-multiple-keys
	IdentityFile %s
	IdentityFile %s
Host no-identity
	User tester
Host non-existent-key
	IdentityFile %s/does_not_exist
Host corrupted-key
	IdentityFile %s/corrupted
Host identities-only
	IdentityFile %s
	IdentitiesOnly yes
`, edKeyPath, edKeyPath, rsaKeyPath, tmpDir, tmpDir, edKeyPath)

	if err := os.WriteFile(filepath.Join(tmpDir, "corrupted"), []byte("not-a-valid-pem-key"), 0600); err != nil {
		t.Fatalf("failed to write corrupted key file: %v", err)
	}

	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	// 1. Single IdentityFile
	cc1, err := cfg.ToClientConfig("with-file-key")
	if err != nil {
		t.Fatalf("failed ToClientConfig with file key: %v", err)
	}
	if len(cc1.Auth) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(cc1.Auth))
	}

	// 2. Multiple IdentityFiles
	cc2, err := cfg.ToClientConfig("with-multiple-keys")
	if err != nil {
		t.Fatalf("failed ToClientConfig with multiple keys: %v", err)
	}
	if len(cc2.Auth) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(cc2.Auth))
	}

	// 3. Fallback via defaultKeys parameter (both file path and in-memory PEM string)
	cc3, err := cfg.ToClientConfig("no-identity", rsaKeyPath)
	if err != nil {
		t.Fatalf("failed ToClientConfig with defaultKeys: %v", err)
	}
	if len(cc3.Auth) != 1 {
		t.Fatalf("expected 1 auth method for defaultKeys, got %d", len(cc3.Auth))
	}

	ccPEM, err := cfg.ToClientConfig("no-identity", edKeyPEM)
	if err != nil {
		t.Fatalf("failed ToClientConfig with in-memory PEM: %v", err)
	}
	if len(ccPEM.Auth) != 1 {
		t.Fatalf("expected 1 auth method for in-memory PEM, got %d", len(ccPEM.Auth))
	}

	// 4. Non-existent key file is skipped gracefully
	ccMissing, err := cfg.ToClientConfig("non-existent-key")
	if err != nil {
		t.Fatalf("non-existent key should be skipped gracefully, got: %v", err)
	}
	if ccMissing == nil {
		t.Fatalf("expected non-nil ClientConfig")
	}

	// 5. Corrupted key file produces an error
	_, err = cfg.ToClientConfig("corrupted-key")
	if err == nil {
		t.Fatalf("expected error for corrupted key file, got nil")
	}

	// 6. IdentitiesOnly ignores defaultKeys
	ccIdentitiesOnly, err := cfg.ToClientConfig("identities-only", rsaKeyPath)
	if err != nil {
		t.Fatalf("failed ToClientConfig with identities-only: %v", err)
	}
	if len(ccIdentitiesOnly.Auth) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(ccIdentitiesOnly.Auth))
	}
}

func TestToClientConfigAlgorithmsAndTimeout(t *testing.T) {
	configText := `
Host options-host
	Ciphers aes128-ctr,aes256-ctr
	MACs hmac-sha2-256,hmac-sha2-512
	KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
	HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
	ConnectTimeout 15
	StrictHostKeyChecking no
Host bad-timeout
	ConnectTimeout notanumber
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	cc, err := cfg.ToClientConfig("options-host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cc.Ciphers) != 2 || cc.Ciphers[0] != "aes128-ctr" || cc.Ciphers[1] != "aes256-ctr" {
		t.Errorf("unexpected Ciphers: %v", cc.Ciphers)
	}
	if len(cc.MACs) != 2 || cc.MACs[0] != "hmac-sha2-256" || cc.MACs[1] != "hmac-sha2-512" {
		t.Errorf("unexpected MACs: %v", cc.MACs)
	}
	if len(cc.KeyExchanges) != 2 || cc.KeyExchanges[0] != "curve25519-sha256" {
		t.Errorf("unexpected KeyExchanges: %v", cc.KeyExchanges)
	}
	if len(cc.HostKeyAlgorithms) != 2 || cc.HostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Errorf("unexpected HostKeyAlgorithms: %v", cc.HostKeyAlgorithms)
	}
	if cc.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", cc.Timeout)
	}

	// StrictHostKeyChecking no allows any host key
	if cc.HostKeyCallback == nil {
		t.Fatalf("expected non-nil HostKeyCallback")
	}
	dummyAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")
	_, pub := generateTestEd25519Key(t)
	if err := cc.HostKeyCallback("dummy:22", dummyAddr, pub); err != nil {
		t.Errorf("InsecureIgnoreHostKey callback should not return error, got: %v", err)
	}

	// Bad timeout error
	if _, err := cfg.ToClientConfig("bad-timeout"); err == nil {
		t.Errorf("expected error for non-numeric ConnectTimeout, got nil")
	}
}

func TestToClientConfigKnownHosts(t *testing.T) {
	tmpDir := t.TempDir()
	_, pub := generateTestEd25519Key(t)

	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	knownHostsLine := fmt.Sprintf("target.server %s %s\n", pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal()))
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsLine), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	configText := fmt.Sprintf(`
Host target.server
	UserKnownHostsFile %s
	StrictHostKeyChecking yes
`, knownHostsPath)

	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	cc, err := cfg.ToClientConfig("target.server")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dummyAddr, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:22")
	if err := cc.HostKeyCallback("target.server:22", dummyAddr, pub); err != nil {
		t.Errorf("expected matching host key to succeed, got: %v", err)
	}

	_, otherPub := generateTestEd25519Key(t)
	if err := cc.HostKeyCallback("target.server:22", dummyAddr, otherPub); err == nil {
		t.Errorf("expected mismatching host key to fail, got nil")
	}
}

func TestUserSettingsAndPackageFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "ssh_config")
	configContent := `
Host prod
	Hostname prod.internal
	Port 2200
	User admin
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write custom config: %v", err)
	}

	us := &UserSettings{
		userConfigFinder: func() string {
			return configPath
		},
	}

	cc, err := us.ToClientConfig("prod")
	if err != nil {
		t.Fatalf("UserSettings.ToClientConfig failed: %v", err)
	}
	if cc.User != "admin" {
		t.Errorf("expected user 'admin', got %q", cc.User)
	}

	port, err := us.Port("prod")
	if err != nil {
		t.Fatalf("UserSettings.Port failed: %v", err)
	}
	if port != 2200 {
		t.Errorf("expected port 2200, got %d", port)
	}

	addr, err := us.Address("prod")
	if err != nil {
		t.Fatalf("UserSettings.Address failed: %v", err)
	}
	if addr != "prod.internal:2200" {
		t.Errorf("expected address prod.internal:2200, got %q", addr)
	}
}
