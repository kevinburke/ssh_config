package ssh_config

import (
	"fmt"
	"strconv"
	"strings"
)

// Default returns the default value for the given keyword, for example "22" if
// the keyword is "Port". Default returns the empty string if the keyword has no
// default, or if the keyword is unknown. Keyword matching is case-insensitive.
//
// Default values are sourced from the openssh-portable source code. To
// validate or update these defaults, check fill_default_options() in
// readconf.c and the algorithm lists in myproposal.h:
//
//	https://github.com/openssh/openssh-portable/blob/master/readconf.c
//	https://github.com/openssh/openssh-portable/blob/master/myproposal.h
func Default(keyword string) string {
	return defaults[strings.ToLower(keyword)]
}

// Arguments where the value must be "yes" or "no" and *only* yes or no.
var yesnos = map[string]bool{
	strings.ToLower("BatchMode"):                        true,
	strings.ToLower("CanonicalizeFallbackLocal"):        true,
	strings.ToLower("CheckHostIP"):                      true,
	strings.ToLower("ClearAllForwardings"):              true,
	strings.ToLower("Compression"):                      true,
	strings.ToLower("EnableSSHKeysign"):                 true,
	strings.ToLower("ExitOnForwardFailure"):             true,
	strings.ToLower("ForwardX11"):                       true,
	strings.ToLower("ForwardX11Trusted"):                true,
	strings.ToLower("GatewayPorts"):                     true,
	strings.ToLower("GSSAPIAuthentication"):             true,
	strings.ToLower("GSSAPIDelegateCredentials"):        true,
	strings.ToLower("HostbasedAuthentication"):          true,
	strings.ToLower("IdentitiesOnly"):                   true,
	strings.ToLower("KbdInteractiveAuthentication"):     true,
	strings.ToLower("NoHostAuthenticationForLocalhost"): true,
	strings.ToLower("PasswordAuthentication"):           true,
	strings.ToLower("PermitLocalCommand"):               true,
	strings.ToLower("PubkeyAuthentication"):             true,
	strings.ToLower("StreamLocalBindUnlink"):            true,
	strings.ToLower("TCPKeepAlive"):                     true,
	strings.ToLower("UseKeychain"):                      true,
	strings.ToLower("VisualHostKey"):                    true,
}

var uints = map[string]bool{
	strings.ToLower("CanonicalizeMaxDots"):     true,
	strings.ToLower("ConnectionAttempts"):      true,
	strings.ToLower("ConnectTimeout"):          true,
	strings.ToLower("NumberOfPasswordPrompts"): true,
	strings.ToLower("Port"):                    true,
	strings.ToLower("ServerAliveCountMax"):     true,
	strings.ToLower("ServerAliveInterval"):     true,
}

func mustBeYesOrNo(lkey string) bool {
	return yesnos[lkey]
}

func mustBeUint(lkey string) bool {
	return uints[lkey]
}

func validate(key, val string) error {
	lkey := strings.ToLower(key)
	if mustBeYesOrNo(lkey) && (val != "yes" && val != "no") {
		return fmt.Errorf("ssh_config: value for key %q must be 'yes' or 'no', got %q", key, val)
	}
	if mustBeUint(lkey) {
		_, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("ssh_config: %v", err)
		}
	}
	return nil
}

// defaultPKAlg is the default value for HostKeyAlgorithms,
// HostbasedAcceptedAlgorithms, and PubkeyAcceptedAlgorithms.
// Sourced from KEX_DEFAULT_PK_ALG in myproposal.h.
var defaultPKAlg = strings.Join([]string{
	"ssh-ed25519-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	"sk-ssh-ed25519-cert-v01@openssh.com",
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"rsa-sha2-512-cert-v01@openssh.com",
	"rsa-sha2-256-cert-v01@openssh.com",
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com",
	"sk-ecdsa-sha2-nistp256@openssh.com",
	"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	"rsa-sha2-512",
	"rsa-sha2-256",
}, ",")

var defaults = map[string]string{
	strings.ToLower("AddKeysToAgent"):            "no",
	strings.ToLower("AddressFamily"):             "any",
	strings.ToLower("BatchMode"):                 "no",
	strings.ToLower("CanonicalizeFallbackLocal"): "yes",
	strings.ToLower("CanonicalizeHostname"):      "no",
	strings.ToLower("CanonicalizeMaxDots"):       "1",
	strings.ToLower("CheckHostIP"):               "no",
	strings.ToLower("Ciphers"):                   "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr",
	strings.ToLower("ClearAllForwardings"):       "no",
	strings.ToLower("Compression"):               "no",
	strings.ToLower("ConnectionAttempts"):        "1",
	strings.ToLower("ControlMaster"):             "no",
	strings.ToLower("ControlPersist"):            "no",
	strings.ToLower("EnableSSHKeysign"):          "no",
	strings.ToLower("EscapeChar"):                "~",
	strings.ToLower("ExitOnForwardFailure"):      "no",
	strings.ToLower("FingerprintHash"):           "sha256",
	strings.ToLower("ForwardAgent"):              "no",
	strings.ToLower("ForwardX11"):                "no",
	strings.ToLower("ForwardX11Timeout"):         "1200",
	strings.ToLower("ForwardX11Trusted"):         "no",
	strings.ToLower("GatewayPorts"):              "no",
	strings.ToLower("GlobalKnownHostsFile"):      "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
	strings.ToLower("GSSAPIAuthentication"):      "no",
	strings.ToLower("GSSAPIDelegateCredentials"): "no",
	strings.ToLower("HashKnownHosts"):            "no",
	strings.ToLower("HostbasedAuthentication"):   "no",

	strings.ToLower("CASignatureAlgorithms"): "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256",

	// HostbasedAcceptedAlgorithms and HostbasedKeyTypes (obsolete alias)
	// both default to KEX_DEFAULT_PK_ALG.
	strings.ToLower("HostbasedAcceptedAlgorithms"): defaultPKAlg,
	strings.ToLower("HostbasedKeyTypes"):           defaultPKAlg,

	strings.ToLower("HostKeyAlgorithms"): defaultPKAlg,
	// HostName has a dynamic default (the value passed at the command line).

	strings.ToLower("IdentitiesOnly"): "no",

	// IPQoS has a dynamic default based on interactive or non-interactive
	// sessions.

	strings.ToLower("KbdInteractiveAuthentication"): "yes",

	strings.ToLower("KexAlgorithms"): "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
	strings.ToLower("LogLevel"):      "INFO",
	strings.ToLower("MACs"):          "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",

	strings.ToLower("NoHostAuthenticationForLocalhost"): "no",
	strings.ToLower("NumberOfPasswordPrompts"):          "3",
	strings.ToLower("PasswordAuthentication"):           "yes",
	strings.ToLower("PermitLocalCommand"):               "no",
	strings.ToLower("Port"):                             "22",

	strings.ToLower("PreferredAuthentications"): "gssapi-with-mic,hostbased,publickey,keyboard-interactive,password",
	strings.ToLower("ProxyUseFdpass"):           "no",

	// PubkeyAcceptedAlgorithms and PubkeyAcceptedKeyTypes (obsolete alias)
	// both default to KEX_DEFAULT_PK_ALG.
	strings.ToLower("PubkeyAcceptedAlgorithms"): defaultPKAlg,
	strings.ToLower("PubkeyAcceptedKeyTypes"):   defaultPKAlg,

	strings.ToLower("PubkeyAuthentication"): "yes",
	strings.ToLower("RekeyLimit"):           "default none",
	strings.ToLower("RequestTTY"):           "auto",

	strings.ToLower("ServerAliveCountMax"):   "3",
	strings.ToLower("ServerAliveInterval"):   "0",
	strings.ToLower("SessionType"):           "default",
	strings.ToLower("StreamLocalBindMask"):   "0177",
	strings.ToLower("StreamLocalBindUnlink"): "no",
	strings.ToLower("StrictHostKeyChecking"): "ask",
	strings.ToLower("TCPKeepAlive"):          "yes",
	strings.ToLower("Tunnel"):                "no",
	strings.ToLower("TunnelDevice"):          "any:any",
	strings.ToLower("UpdateHostKeys"):        "yes",
	strings.ToLower("UseKeychain"):           "no",

	strings.ToLower("UserKnownHostsFile"): "~/.ssh/known_hosts ~/.ssh/known_hosts2",
	strings.ToLower("VerifyHostKeyDNS"):   "no",
	strings.ToLower("VisualHostKey"):      "no",
	strings.ToLower("XAuthLocation"):      "/usr/X11R6/bin/xauth",
}

// defaultIdentityFiles are the default IdentityFile values.
// Sourced from fill_default_options() in readconf.c.
var defaultIdentityFiles = []string{
	"~/.ssh/id_rsa",
	"~/.ssh/id_ecdsa",
	"~/.ssh/id_ecdsa_sk",
	"~/.ssh/id_ed25519",
	"~/.ssh/id_ed25519_sk",
}

// these directives support multiple items that can be collected
// across multiple files
var pluralDirectives = map[string]bool{
	"CertificateFile": true,
	"IdentityFile":    true,
	"DynamicForward":  true,
	"RemoteForward":   true,
	"SendEnv":         true,
	"SetEnv":          true,
}

// SupportsMultiple reports whether a directive can be specified multiple times.
func SupportsMultiple(key string) bool {
	return pluralDirectives[strings.ToLower(key)]
}
