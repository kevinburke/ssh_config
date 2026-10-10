package ssh_config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func generateTestPrivateKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8 private key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}
	return pem.EncodeToMemory(pemBlock), sshPub
}

func TestClientConfigBasic(t *testing.T) {
	configText := `
Host test-server
    HostName 192.168.1.100
    Port 2222
    User devuser
    ConnectTimeout 10
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	clientCfg, err := cfg.ClientConfig("test-server")
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	if clientCfg.User != "devuser" {
		t.Errorf("expected User %q, got %q", "devuser", clientCfg.User)
	}
	if clientCfg.Timeout != 10*time.Second {
		t.Errorf("expected Timeout %v, got %v", 10*time.Second, clientCfg.Timeout)
	}
	if clientCfg.HostKeyCallback == nil {
		t.Fatal("expected non-nil HostKeyCallback")
	}

	// StrictHostKeyChecking no should accept any key
	dummyAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 2222}
	_, testPub := generateTestPrivateKey(t)
	if err := clientCfg.HostKeyCallback("192.168.1.100:2222", dummyAddr, testPub); err != nil {
		t.Errorf("expected InsecureIgnoreHostKey to succeed, got %v", err)
	}

	addr := cfg.Address("test-server")
	if addr != "192.168.1.100:2222" {
		t.Errorf("expected Address %q, got %q", "192.168.1.100:2222", addr)
	}
}

func TestClientConfigDefaultUser(t *testing.T) {
	configText := `
Host anonymous
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	clientCfg, err := cfg.ClientConfig("anonymous")
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	expected := defaultUser()
	if clientCfg.User != expected {
		t.Errorf("expected default User %q, got %q", expected, clientCfg.User)
	}
}

func TestClientConfigWithOptions(t *testing.T) {
	configText := `
Host example.com
    User original
    ConnectTimeout 5
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	bannerCalled := false
	bannerFn := func(message string) error {
		bannerCalled = true
		return nil
	}

	customTimeout := 45 * time.Second
	clientCfg, err := cfg.ClientConfig("example.com",
		WithUser("override-user"),
		WithTimeout(customTimeout),
		WithClientVersion("SSH-2.0-CustomTest"),
		WithBannerCallback(bannerFn),
	)
	if err != nil {
		t.Fatalf("ClientConfig with options failed: %v", err)
	}

	if clientCfg.User != "override-user" {
		t.Errorf("expected User override %q, got %q", "override-user", clientCfg.User)
	}
	if clientCfg.Timeout != customTimeout {
		t.Errorf("expected Timeout %v, got %v", customTimeout, clientCfg.Timeout)
	}
	if clientCfg.ClientVersion != "SSH-2.0-CustomTest" {
		t.Errorf("expected ClientVersion %q, got %q", "SSH-2.0-CustomTest", clientCfg.ClientVersion)
	}
	if clientCfg.BannerCallback == nil {
		t.Fatal("expected non-nil BannerCallback")
	}
	_ = clientCfg.BannerCallback("test")
	if !bannerCalled {
		t.Errorf("expected banner callback to be called")
	}
}

func TestClientConfigAlgorithms(t *testing.T) {
	configText := `
Host secure-box
    Ciphers aes128-ctr,aes256-ctr
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
    MACs hmac-sha2-256,hmac-sha2-512
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	clientCfg, err := cfg.ClientConfig("secure-box")
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	expectedCiphers := []string{"aes128-ctr", "aes256-ctr"}
	if !reflect.DeepEqual(clientCfg.Ciphers, expectedCiphers) {
		t.Errorf("expected Ciphers %v, got %v", expectedCiphers, clientCfg.Ciphers)
	}

	expectedKex := []string{"curve25519-sha256", "ecdh-sha2-nistp256"}
	if !reflect.DeepEqual(clientCfg.KeyExchanges, expectedKex) {
		t.Errorf("expected KeyExchanges %v, got %v", expectedKex, clientCfg.KeyExchanges)
	}

	expectedMACs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	if !reflect.DeepEqual(clientCfg.MACs, expectedMACs) {
		t.Errorf("expected MACs %v, got %v", expectedMACs, clientCfg.MACs)
	}

	expectedHostKeyAlgos := []string{"ssh-ed25519", "rsa-sha2-512"}
	if !reflect.DeepEqual(clientCfg.HostKeyAlgorithms, expectedHostKeyAlgos) {
		t.Errorf("expected HostKeyAlgorithms %v, got %v", expectedHostKeyAlgos, clientCfg.HostKeyAlgorithms)
	}
}

func TestClientConfigRekeyLimit(t *testing.T) {
	tests := []struct {
		val      string
		expected uint64
	}{
		{"1G", 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"64K", 64 * 1024},
		{"2048", 2048},
		{"default none", 0},
		{"none", 0},
	}

	for _, tt := range tests {
		configText := "Host rekey-host\n    RekeyLimit " + tt.val + "\n"
		cfg, err := Decode(strings.NewReader(configText))
		if err != nil {
			t.Fatalf("Decode failed for RekeyLimit %q: %v", tt.val, err)
		}

		clientCfg, err := cfg.ClientConfig("rekey-host")
		if err != nil {
			t.Fatalf("ClientConfig failed for RekeyLimit %q: %v", tt.val, err)
		}

		if clientCfg.RekeyThreshold != tt.expected {
			t.Errorf("for RekeyLimit %q expected %d, got %d", tt.val, tt.expected, clientCfg.RekeyThreshold)
		}
	}
}

func TestClientConfigIdentityFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_test_ed25519")

	keyBytes, expectedPub := generateTestPrivateKey(t)
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	configText := `
Host identity-test
    IdentityFile ` + keyPath + `
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	clientCfg, err := cfg.ClientConfig("identity-test")
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	if len(clientCfg.Auth) == 0 {
		t.Fatal("expected at least one Auth method")
	}

	// Verify the parsed signer matches the expected public key
	expectedSigner, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	if string(expectedSigner.PublicKey().Marshal()) != string(expectedPub.Marshal()) {
		t.Errorf("public key mismatch")
	}
}

func TestClientConfigEncryptedIdentityFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_encrypted")

	// OpenSSH formatted encrypted ed25519 key sample
	encryptedPEM := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABASdI62cO
cT0K13E1R3b0g7AAAAEAAAAAEAAAAzAAAAM2Z2bmV0LXNpZy1zb2Z0d2FyZQAAAAABAACJ
4f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
-----END OPENSSH PRIVATE KEY-----`

	if err := os.WriteFile(keyPath, []byte(encryptedPEM), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	configText := `
Host enc-test
    IdentityFile ` + keyPath + `
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Expect error without passphrase
	_, err = cfg.ClientConfig("enc-test")
	if err == nil {
		t.Errorf("expected error when parsing encrypted key without passphrase")
	}
}

func TestClientConfigNonexistentIdentityFile(t *testing.T) {
	configText := `
Host ghost-identity
    IdentityFile /nonexistent/path/to/key
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Non-existent identity files should be skipped without error
	clientCfg, err := cfg.ClientConfig("ghost-identity")
	if err != nil {
		t.Fatalf("expected non-existent identity file to be skipped, got: %v", err)
	}
	if clientCfg == nil {
		t.Fatal("expected non-nil ClientConfig")
	}
}

func TestClientConfigWithAuthMethodsAndSigners(t *testing.T) {
	configText := `
Host custom-auth
    StrictHostKeyChecking no
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	keyBytes, _ := generateTestPrivateKey(t)
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	customPassAuth := ssh.Password("secure-password")
	clientCfg, err := cfg.ClientConfig("custom-auth",
		WithAuthMethods(customPassAuth),
		WithSigners(signer),
	)
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	if len(clientCfg.Auth) < 2 {
		t.Errorf("expected at least 2 Auth methods, got %d", len(clientCfg.Auth))
	}
}

func TestClientConfigKnownHosts(t *testing.T) {
	tmpDir := t.TempDir()
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")

	_, serverPub := generateTestPrivateKey(t)
	line := knownhosts.Line([]string{"192.168.1.200:22"}, serverPub) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0644); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	configText := `
Host known-server
    HostName 192.168.1.200
    UserKnownHostsFile ` + knownHostsPath + `
    StrictHostKeyChecking yes
`
	cfg, err := Decode(strings.NewReader(configText))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	clientCfg, err := cfg.ClientConfig("known-server")
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}

	dummyAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.200"), Port: 22}
	// Check that the callback accepts the known server key
	if err := clientCfg.HostKeyCallback("192.168.1.200:22", dummyAddr, serverPub); err != nil {
		t.Errorf("HostKeyCallback rejected known key: %v", err)
	}

	// Check that the callback rejects an unknown key
	_, unknownPub := generateTestPrivateKey(t)
	if err := clientCfg.HostKeyCallback("192.168.1.200:22", dummyAddr, unknownPub); err == nil {
		t.Errorf("expected HostKeyCallback to reject unknown key")
	}
}

func TestAddressHelper(t *testing.T) {
	tests := []struct {
		config   string
		alias    string
		expected string
	}{
		{
			config:   "Host web\n    HostName 10.0.0.1\n    Port 8022\n",
			alias:    "web",
			expected: "10.0.0.1:8022",
		},
		{
			config:   "Host db\n    Port 3306\n",
			alias:    "db",
			expected: "db:3306",
		},
		{
			config:   "Host default-box\n",
			alias:    "default-box",
			expected: "default-box:22",
		},
		{
			config:   "Host ipv6\n    HostName ::1\n    Port 22\n",
			alias:    "ipv6",
			expected: "[::1]:22",
		},
	}

	for _, tt := range tests {
		cfg, err := Decode(strings.NewReader(tt.config))
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		addr := cfg.Address(tt.alias)
		if addr != tt.expected {
			t.Errorf("cfg.Address(%q) = %q; want %q", tt.alias, addr, tt.expected)
		}
	}
}

func TestExpandTokens(t *testing.T) {
	vars := map[string]string{
		"d": "/home/testuser",
		"u": "testuser",
		"h": "example.com",
		"p": "2222",
		"r": "admin",
		"l": "my-laptop",
	}

	tests := []struct {
		input    string
		homeDir  string
		expected string
	}{
		{"~/.ssh/id_rsa", "/home/testuser", "/home/testuser/.ssh/id_rsa"},
		{"/keys/%u/%h_key", "/home/testuser", "/keys/testuser/example.com_key"},
		{"/keys/%r_%p", "/home/testuser", "/keys/admin_2222"},
		{"%%literal%%", "/home/testuser", "%literal%"},
		{"/static/path", "/home/testuser", "/static/path"},
	}

	for _, tt := range tests {
		got := expandTokens(tt.input, tt.homeDir, vars)
		if got != tt.expected {
			t.Errorf("expandTokens(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestUserSettingsClientConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "ssh_config")

	content := `
Host myserver
    User deploy
    Port 9922
    StrictHostKeyChecking no
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	us := &UserSettings{
		userConfigFinder: testConfigFinder(configFile),
	}

	clientCfg, err := us.ClientConfig("myserver")
	if err != nil {
		t.Fatalf("us.ClientConfig failed: %v", err)
	}
	if clientCfg.User != "deploy" {
		t.Errorf("expected User deploy, got %q", clientCfg.User)
	}

	addr := us.Address("myserver")
	if addr != "myserver:9922" {
		t.Errorf("expected Address myserver:9922, got %q", addr)
	}
}

func TestTopLevelClientConfig(t *testing.T) {
	// Calling top-level ClientConfig on an arbitrary non-configured host should succeed
	// using system defaults (default user, port 22, valid HostKeyCallback).
	clientCfg, err := ClientConfig("unconfigured-host-test", WithHostKeyCallback(ssh.InsecureIgnoreHostKey()))
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}
	if clientCfg == nil {
		t.Fatal("expected non-nil client config")
	}
	if clientCfg.User == "" {
		t.Errorf("expected non-empty default user")
	}

	addr := Address("unconfigured-host-test")
	if addr != "unconfigured-host-test:22" {
		t.Errorf("expected Address unconfigured-host-test:22, got %q", addr)
	}
}
