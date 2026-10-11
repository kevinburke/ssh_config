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

type configReader interface {
	get(alias, key string) (string, error)
	getAll(alias, key string) ([]string, error)
}

type configAdapter struct {
	c *Config
}

func (a *configAdapter) get(alias, key string) (string, error) {
	val, err := a.c.Get(alias, key)
	if err != nil {
		return "", err
	}
	if val == "" {
		val = Default(key)
	}
	if val != "" {
		if err := validate(key, val); err != nil {
			return "", err
		}
	}
	return val, nil
}

func (a *configAdapter) getAll(alias, key string) ([]string, error) {
	vals, err := a.c.GetAll(alias, key)
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		if def := Default(key); def != "" {
			return []string{def}, nil
		}
	}
	return vals, nil
}

type userSettingsAdapter struct {
	u *UserSettings
}

func (a *userSettingsAdapter) get(alias, key string) (string, error) {
	return a.u.GetStrict(alias, key)
}

func (a *userSettingsAdapter) getAll(alias, key string) ([]string, error) {
	return a.u.GetAllStrict(alias, key)
}

// ToClientConfig converts the SSH configuration for the given alias into an
// *ssh.ClientConfig suitable for use with ssh.Dial.
//
// defaultKeys are optional paths to private key files to use if no IdentityFile
// directives are present in the configuration, or to try as fallbacks.
func ToClientConfig(alias string, defaultKeys ...string) (*ssh.ClientConfig, error) {
	return DefaultUserSettings.ToClientConfig(alias, defaultKeys...)
}

// Address returns the target address (hostname:port) for the given alias.
// If Hostname is not specified, alias is used as the hostname.
// If Port is not specified, the default SSH port (22) is used.
func Address(alias string) (string, error) {
	return DefaultUserSettings.Address(alias)
}

// Port returns the configured port as an integer for the given alias.
// If Port is not specified, 22 is returned.
func Port(alias string) (int, error) {
	return DefaultUserSettings.Port(alias)
}

// ToClientConfig converts the SSH configuration for the given alias into an
// *ssh.ClientConfig suitable for use with ssh.Dial.
func (u *UserSettings) ToClientConfig(alias string, defaultKeys ...string) (*ssh.ClientConfig, error) {
	return toClientConfig(&userSettingsAdapter{u: u}, alias, defaultKeys...)
}

// Address returns the target address (hostname:port) for the given alias.
func (u *UserSettings) Address(alias string) (string, error) {
	return getAddress(&userSettingsAdapter{u: u}, alias)
}

// Port returns the configured port as an integer for the given alias.
func (u *UserSettings) Port(alias string) (int, error) {
	return getPort(&userSettingsAdapter{u: u}, alias)
}

// ToClientConfig converts the SSH configuration for the given alias into an
// *ssh.ClientConfig suitable for use with ssh.Dial.
func (c *Config) ToClientConfig(alias string, defaultKeys ...string) (*ssh.ClientConfig, error) {
	return toClientConfig(&configAdapter{c: c}, alias, defaultKeys...)
}

// Address returns the target address (hostname:port) for the given alias.
func (c *Config) Address(alias string) (string, error) {
	return getAddress(&configAdapter{c: c}, alias)
}

// Port returns the configured port as an integer for the given alias.
func (c *Config) Port(alias string) (int, error) {
	return getPort(&configAdapter{c: c}, alias)
}

func getPort(r configReader, alias string) (int, error) {
	portStr, err := r.get(alias, "Port")
	if err != nil {
		return 0, err
	}
	if portStr == "" {
		return 22, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("ssh_config: invalid port %q for %s", portStr, alias)
	}
	return port, nil
}

func getAddress(r configReader, alias string) (string, error) {
	hostname, err := r.get(alias, "Hostname")
	if err != nil {
		return "", err
	}
	if hostname == "" {
		hostname = alias
	}
	port, err := getPort(r, alias)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(hostname, strconv.Itoa(port)), nil
}

func toClientConfig(r configReader, alias string, defaultKeys ...string) (*ssh.ClientConfig, error) {
	user, err := r.get(alias, "User")
	if err != nil {
		return nil, err
	}
	if user == "" {
		if curUser, err := osuser.Current(); err == nil && curUser.Username != "" {
			user = curUser.Username
		} else if envUser := os.Getenv("USER"); envUser != "" {
			user = envUser
		} else if envUser := os.Getenv("LOGNAME"); envUser != "" {
			user = envUser
		}
	}

	if _, err := getPort(r, alias); err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User: user,
	}

	timeoutStr, err := r.get(alias, "ConnectTimeout")
	if err != nil {
		return nil, err
	}
	if timeoutStr != "" {
		secs, err := strconv.Atoi(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf("ssh_config: invalid ConnectTimeout %q: %w", timeoutStr, err)
		}
		if secs > 0 {
			clientConfig.Timeout = time.Duration(secs) * time.Second
		}
	}

	if ciphers, err := r.get(alias, "Ciphers"); err == nil && ciphers != "" {
		clientConfig.Ciphers = splitList(ciphers)
	}
	if kex, err := r.get(alias, "KexAlgorithms"); err == nil && kex != "" {
		clientConfig.KeyExchanges = splitList(kex)
	}
	if macs, err := r.get(alias, "MACs"); err == nil && macs != "" {
		clientConfig.MACs = splitList(macs)
	}
	if hka, err := r.get(alias, "HostKeyAlgorithms"); err == nil && hka != "" {
		clientConfig.HostKeyAlgorithms = splitList(hka)
	}

	strictVal, _ := r.get(alias, "StrictHostKeyChecking")
	if strings.EqualFold(strictVal, "no") {
		clientConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		knownHostsVal, _ := r.get(alias, "UserKnownHostsFile")
		var candidateFiles []string
		if knownHostsVal != "" {
			for _, f := range strings.Fields(knownHostsVal) {
				candidateFiles = append(candidateFiles, expandPath(f))
			}
		} else {
			candidateFiles = []string{
				expandPath("~/.ssh/known_hosts"),
				expandPath("~/.ssh/known_hosts2"),
			}
		}

		var existingFiles []string
		for _, f := range candidateFiles {
			if _, err := os.Stat(f); err == nil {
				existingFiles = append(existingFiles, f)
			}
		}

		if len(existingFiles) > 0 {
			cb, err := knownhosts.New(existingFiles...)
			if err != nil {
				return nil, fmt.Errorf("ssh_config: error loading known hosts: %w", err)
			}
			clientConfig.HostKeyCallback = cb
		} else {
			cb, err := knownhosts.New()
			if err != nil {
				clientConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
			} else {
				clientConfig.HostKeyCallback = cb
			}
		}
	}

	identitiesOnlyVal, _ := r.get(alias, "IdentitiesOnly")
	identitiesOnly := strings.EqualFold(identitiesOnlyVal, "yes")

	idFiles, err := r.getAll(alias, "IdentityFile")
	if err != nil {
		return nil, err
	}

	var keyCandidates []string
	for _, f := range idFiles {
		f = strings.TrimSpace(f)
		if f != "" {
			keyCandidates = append(keyCandidates, f)
		}
	}

	if !identitiesOnly {
		for _, k := range defaultKeys {
			k = strings.TrimSpace(k)
			if k != "" {
				keyCandidates = append(keyCandidates, k)
			}
		}
		if len(keyCandidates) == 0 {
			for _, def := range defaultIdentityFiles {
				keyCandidates = append(keyCandidates, def)
			}
		}
	}

	keyCandidates = removeDups(keyCandidates)

	var signers []ssh.Signer
	for _, item := range keyCandidates {
		signer, err := parseSigner(item)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("ssh_config: error parsing private key %s: %w", item, err)
		}
		if signer != nil {
			signers = append(signers, signer)
		}
	}

	if !identitiesOnly {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				defer conn.Close()
				agentClient := agent.NewClient(conn)
				if agentSigners, err := agentClient.Signers(); err == nil {
					signers = append(signers, agentSigners...)
				}
			}
		}
	}

	if len(signers) > 0 {
		clientConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}
	}

	return clientConfig, nil
}

func parseSigner(keyOrPath string) (ssh.Signer, error) {
	if strings.Contains(keyOrPath, "-----BEGIN ") {
		return ssh.ParsePrivateKey([]byte(keyOrPath))
	}
	path := expandPath(keyOrPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func expandPath(path string) string {
	path = strings.Trim(path, "\"'")
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homedir(), path[2:])
	}
	if path == "~" {
		return homedir()
	}
	return path
}

func splitList(val string) []string {
	parts := strings.Split(val, ",")
	var res []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}
