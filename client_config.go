package ssh_config

import (
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ClientConfigOption configures client configuration options.
type ClientConfigOption func(*clientConfigOptions)

type clientConfigOptions struct {
	authMethods     []ssh.AuthMethod
	signers         []ssh.Signer
	passphrase      []byte
	hostKeyCallback ssh.HostKeyCallback
	knownHostsFiles []string
	useAgent        *bool
	user            string
	timeout         *time.Duration
	bannerCallback  ssh.BannerCallback
	clientVersion   string
}

// WithAuthMethods appends custom SSH authentication methods.
func WithAuthMethods(methods ...ssh.AuthMethod) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.authMethods = append(opts.authMethods, methods...)
	}
}

// WithSigners appends private key signers for public key authentication.
func WithSigners(signers ...ssh.Signer) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.signers = append(opts.signers, signers...)
	}
}

// WithPassphrase sets the decryption passphrase for encrypted private keys.
func WithPassphrase(passphrase []byte) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.passphrase = passphrase
	}
}

// WithHostKeyCallback sets an explicit host key validation callback.
func WithHostKeyCallback(cb ssh.HostKeyCallback) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.hostKeyCallback = cb
	}
}

// WithKnownHostsFiles appends additional known_hosts files to check.
func WithKnownHostsFiles(files ...string) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.knownHostsFiles = append(opts.knownHostsFiles, files...)
	}
}

// WithAgent controls whether ssh-agent authentication is attempted.
func WithAgent(enable bool) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.useAgent = &enable
	}
}

// WithUser overrides the username for the SSH client connection.
func WithUser(user string) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.user = user
	}
}

// WithTimeout overrides the connection timeout.
func WithTimeout(d time.Duration) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.timeout = &d
	}
}

// WithBannerCallback sets the banner display callback.
func WithBannerCallback(cb ssh.BannerCallback) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.bannerCallback = cb
	}
}

// WithClientVersion overrides the client version identification string.
func WithClientVersion(version string) ClientConfigOption {
	return func(opts *clientConfigOptions) {
		opts.clientVersion = version
	}
}

type configSource interface {
	getExplicit(alias, key string) (string, error)
	getAllExplicit(alias, key string) ([]string, error)
	get(alias, key string) (string, error)
	getAll(alias, key string) ([]string, error)
}

type userSettingsSource struct {
	u *UserSettings
}

func (s *userSettingsSource) getExplicit(alias, key string) (string, error) {
	s.u.doLoadConfigs()
	if s.u.onceErr != nil && !s.u.IgnoreErrors {
		return "", s.u.onceErr
	}
	if s.u.customConfig != nil {
		if val, err := findVal(s.u.customConfig, alias, key); err != nil || val != "" {
			return val, err
		}
	}
	if s.u.userConfig != nil {
		if val, err := findVal(s.u.userConfig, alias, key); err != nil || val != "" {
			return val, err
		}
	}
	if s.u.systemConfig != nil {
		if val, err := findVal(s.u.systemConfig, alias, key); err != nil || val != "" {
			return val, err
		}
	}
	return "", nil
}

func (s *userSettingsSource) getAllExplicit(alias, key string) ([]string, error) {
	s.u.doLoadConfigs()
	if s.u.onceErr != nil && !s.u.IgnoreErrors {
		return nil, s.u.onceErr
	}
	if s.u.customConfig != nil {
		if val, err := findAll(s.u.customConfig, alias, key); err != nil || val != nil {
			return val, err
		}
	}
	if s.u.userConfig != nil {
		if val, err := findAll(s.u.userConfig, alias, key); err != nil || val != nil {
			return val, err
		}
	}
	if s.u.systemConfig != nil {
		if val, err := findAll(s.u.systemConfig, alias, key); err != nil || val != nil {
			return val, err
		}
	}
	return nil, nil
}

func (s *userSettingsSource) get(alias, key string) (string, error) {
	return s.u.GetStrict(alias, key)
}

func (s *userSettingsSource) getAll(alias, key string) ([]string, error) {
	return s.u.GetAllStrict(alias, key)
}

type configSourceAdapter struct {
	c *Config
}

func (s *configSourceAdapter) getExplicit(alias, key string) (string, error) {
	if s.c == nil {
		return "", nil
	}
	return findVal(s.c, alias, key)
}

func (s *configSourceAdapter) getAllExplicit(alias, key string) ([]string, error) {
	if s.c == nil {
		return nil, nil
	}
	return findAll(s.c, alias, key)
}

func (s *configSourceAdapter) get(alias, key string) (string, error) {
	val, err := s.getExplicit(alias, key)
	if err != nil || val != "" {
		return val, err
	}
	return Default(key), nil
}

func (s *configSourceAdapter) getAll(alias, key string) ([]string, error) {
	vals, err := s.getAllExplicit(alias, key)
	if err != nil || len(vals) > 0 {
		return vals, err
	}
	if def := Default(key); def != "" {
		return []string{def}, nil
	}
	return nil, nil
}

func defaultUser() string {
	if u, err := osuser.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if env := os.Getenv("USER"); env != "" {
		return env
	}
	return ""
}

func parseCommaSeparatedList(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseRekeyLimitBytes(val string) (uint64, error) {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return 0, nil
	}
	first := strings.ToUpper(fields[0])
	if first == "DEFAULT" || first == "NONE" {
		return 0, nil
	}
	multiplier := uint64(1)
	if strings.HasSuffix(first, "K") {
		multiplier = 1024
		first = strings.TrimSuffix(first, "K")
	} else if strings.HasSuffix(first, "M") {
		multiplier = 1024 * 1024
		first = strings.TrimSuffix(first, "M")
	} else if strings.HasSuffix(first, "G") {
		multiplier = 1024 * 1024 * 1024
		first = strings.TrimSuffix(first, "G")
	}
	n, err := strconv.ParseUint(first, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ssh_config: invalid RekeyLimit value %q: %w", val, err)
	}
	return n * multiplier, nil
}

func expandTokens(path string, homeDir string, vars map[string]string) string {
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(homeDir, path[2:])
	} else if path == "~" {
		path = homeDir
	}
	if !strings.Contains(path, "%") {
		return path
	}
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+1 < len(path) {
			token := string(path[i+1])
			if val, ok := vars[token]; ok {
				b.WriteString(val)
				i++
				continue
			}
			if path[i+1] == '%' {
				b.WriteByte('%')
				i++
				continue
			}
		}
		b.WriteByte(path[i])
	}
	return b.String()
}

func splitFilePaths(val string) []string {
	var paths []string
	for _, p := range strings.Fields(val) {
		trimmed := strings.Trim(p, "\"")
		if trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	return paths
}

func buildClientConfig(src configSource, alias string, opts []ClientConfigOption) (*ssh.ClientConfig, error) {
	var options clientConfigOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	hostName, err := src.get(alias, "HostName")
	if err != nil {
		return nil, err
	}
	if hostName == "" {
		hostName = alias
	}

	port, err := src.get(alias, "Port")
	if err != nil {
		return nil, err
	}
	if port == "" {
		port = "22"
	}

	var user string
	if options.user != "" {
		user = options.user
	} else {
		user, err = src.get(alias, "User")
		if err != nil {
			return nil, err
		}
		if user == "" {
			user = defaultUser()
		}
	}

	home := homedir()
	localUser := defaultUser()
	localHost, _ := os.Hostname()
	vars := map[string]string{
		"d": home,
		"u": localUser,
		"h": hostName,
		"p": port,
		"r": user,
		"l": localHost,
	}

	cfg := ssh.Config{}

	if val, err := src.getExplicit(alias, "Ciphers"); err != nil {
		return nil, err
	} else if val != "" {
		cfg.Ciphers = parseCommaSeparatedList(val)
	}

	if val, err := src.getExplicit(alias, "KexAlgorithms"); err != nil {
		return nil, err
	} else if val != "" {
		cfg.KeyExchanges = parseCommaSeparatedList(val)
	}

	if val, err := src.getExplicit(alias, "MACs"); err != nil {
		return nil, err
	} else if val != "" {
		cfg.MACs = parseCommaSeparatedList(val)
	}

	if val, err := src.getExplicit(alias, "RekeyLimit"); err != nil {
		return nil, err
	} else if val != "" {
		threshold, err := parseRekeyLimitBytes(val)
		if err != nil {
			return nil, err
		}
		cfg.RekeyThreshold = threshold
	}

	var hostKeyAlgorithms []string
	if val, err := src.getExplicit(alias, "HostKeyAlgorithms"); err != nil {
		return nil, err
	} else if val != "" {
		hostKeyAlgorithms = parseCommaSeparatedList(val)
	}

	var timeout time.Duration
	if options.timeout != nil {
		timeout = *options.timeout
	} else {
		if val, err := src.getExplicit(alias, "ConnectTimeout"); err != nil {
			return nil, err
		} else if val != "" {
			if sec, err := strconv.Atoi(val); err == nil && sec > 0 {
				timeout = time.Duration(sec) * time.Second
			}
		}
	}

	var hostKeyCallback ssh.HostKeyCallback
	if options.hostKeyCallback != nil {
		hostKeyCallback = options.hostKeyCallback
	} else {
		strict, err := src.get(alias, "StrictHostKeyChecking")
		if err != nil {
			return nil, err
		}
		strict = strings.ToLower(strings.TrimSpace(strict))
		if strict == "no" || strict == "off" {
			hostKeyCallback = ssh.InsecureIgnoreHostKey()
		} else {
			var knownHostsFiles []string
			knownHostsFiles = append(knownHostsFiles, options.knownHostsFiles...)

			if userKnown, err := src.get(alias, "UserKnownHostsFile"); err == nil && userKnown != "" {
				for _, f := range splitFilePaths(userKnown) {
					knownHostsFiles = append(knownHostsFiles, expandTokens(f, home, vars))
				}
			}
			if globalKnown, err := src.get(alias, "GlobalKnownHostsFile"); err == nil && globalKnown != "" {
				for _, f := range splitFilePaths(globalKnown) {
					knownHostsFiles = append(knownHostsFiles, expandTokens(f, home, vars))
				}
			}

			var existingFiles []string
			for _, f := range knownHostsFiles {
				if fi, err := os.Stat(f); err == nil && !fi.IsDir() {
					existingFiles = append(existingFiles, f)
				}
			}

			cb, err := knownhosts.New(existingFiles...)
			if err != nil {
				return nil, fmt.Errorf("ssh_config: failed to load known_hosts: %w", err)
			}
			hostKeyCallback = cb
		}
	}

	authMethods := make([]ssh.AuthMethod, 0, len(options.authMethods))
	authMethods = append(authMethods, options.authMethods...)

	var signers []ssh.Signer
	signers = append(signers, options.signers...)

	idFiles, err := src.getAllExplicit(alias, "IdentityFile")
	if err != nil {
		return nil, err
	}
	isDefaultIdentity := false
	if len(idFiles) == 0 {
		idFiles = defaultIdentityFiles
		isDefaultIdentity = true
	}

	for _, rawPath := range idFiles {
		expanded := expandTokens(rawPath, home, vars)
		fi, err := os.Stat(expanded)
		if err != nil || fi.IsDir() {
			continue
		}
		keyBytes, err := os.ReadFile(expanded)
		if err != nil {
			if isDefaultIdentity {
				continue
			}
			return nil, fmt.Errorf("ssh_config: failed to read identity file %q: %w", expanded, err)
		}

		var signer ssh.Signer
		if len(options.passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, options.passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			if isDefaultIdentity {
				continue
			}
			return nil, fmt.Errorf("ssh_config: failed to parse private key %q: %w", expanded, err)
		}
		signers = append(signers, signer)
	}

	if len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}

	useAgent := true
	if options.useAgent != nil {
		useAgent = *options.useAgent
	} else {
		identitiesOnly, err := src.get(alias, "IdentitiesOnly")
		if err == nil && strings.EqualFold(strings.TrimSpace(identitiesOnly), "yes") {
			useAgent = false
		}
	}

	if useAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				ag := agent.NewClient(conn)
				if agentSigners, err := ag.Signers(); err == nil && len(agentSigners) > 0 {
					authMethods = append(authMethods, ssh.PublicKeys(agentSigners...))
				} else {
					conn.Close()
				}
			}
		}
	}

	return &ssh.ClientConfig{
		Config:            cfg,
		User:              user,
		Auth:              authMethods,
		HostKeyCallback:   hostKeyCallback,
		BannerCallback:    options.bannerCallback,
		ClientVersion:     options.clientVersion,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           timeout,
	}, nil
}

// ClientConfig creates an ssh.ClientConfig for alias using DefaultUserSettings.
func ClientConfig(alias string, opts ...ClientConfigOption) (*ssh.ClientConfig, error) {
	return DefaultUserSettings.ClientConfig(alias, opts...)
}

// ClientConfig creates an ssh.ClientConfig for alias using the receiver UserSettings.
func (u *UserSettings) ClientConfig(alias string, opts ...ClientConfigOption) (*ssh.ClientConfig, error) {
	return buildClientConfig(&userSettingsSource{u: u}, alias, opts)
}

// ClientConfig creates an ssh.ClientConfig for alias using the receiver Config.
func (c *Config) ClientConfig(alias string, opts ...ClientConfigOption) (*ssh.ClientConfig, error) {
	return buildClientConfig(&configSourceAdapter{c: c}, alias, opts)
}

// Address returns the destination "host:port" address for alias using DefaultUserSettings.
func Address(alias string) string {
	return DefaultUserSettings.Address(alias)
}

// Address returns the destination "host:port" address for alias using the receiver UserSettings.
func (u *UserSettings) Address(alias string) string {
	host := u.Get(alias, "HostName")
	if host == "" {
		host = alias
	}
	port := u.Get(alias, "Port")
	if port == "" {
		port = "22"
	}
	return net.JoinHostPort(host, port)
}

// Address returns the destination "host:port" address for alias using the receiver Config.
func (c *Config) Address(alias string) string {
	host, _ := c.Get(alias, "HostName")
	if host == "" {
		host = alias
	}
	port, _ := c.Get(alias, "Port")
	if port == "" {
		port = Default("Port")
		if port == "" {
			port = "22"
		}
	}
	return net.JoinHostPort(host, port)
}
