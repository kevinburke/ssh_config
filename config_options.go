package ssh_config

import (
	"strings"
)

// Current as of OpenSSH 8.2
// Source: https://man.openbsd.org/ssh_config
var configOptions = []string{
	"Host",
	"Match",
	"AddKeysToAgent",
	"AddressFamily",
	"BatchMode",
	"BindAddress",
	"BindInterface",
	"CanonicalDomains",
	"CanonicalizeFallbackLocal",
	"CanonicalizeHostname",
	"CanonicalizeMaxDots",
	"CanonicalizePermittedCNAMEs",
	"CASignatureAlgorithms",
	"CertificateFile",
	"CheckHostIP",
	"Ciphers",
	"ClearAllForwardings",
	"Compression",
	"ConnectionAttempts",
	"ConnectTimeout",
	"ControlMaster",
	"ControlPath",
	"ControlPersist",
	"DynamicForward",
	"EnableSSHKeysign",
	"EscapeChar",
	"ExitOnForwardFailure",
	"FingerprintHash",
	"ForkAfterAuthentication",
	"ForwardAgent",
	"ForwardX11",
	"ForwardX11Timeout",
	"ForwardX11Trusted",
	"GatewayPorts",
	"GlobalKnownHostsFile",
	"GSSAPIAuthentication",
	"GSSAPIDelegateCredentials",
	"HashKnownHosts",
	"HostbasedAcceptedAlgorithms",
	"HostbasedAuthentication",
	"HostKeyAlgorithms",
	"HostKeyAlias",
	"Hostname",
	"IdentitiesOnly",
	"IdentityAgent",
	"IdentityFile",
	"IgnoreUnknown",
	"Include",
	"IPQoS",
	"KbdInteractiveAuthentication",
	"KbdInteractiveDevices",
	"KexAlgorithms",
	"KnownHostsCommand",
	"LocalCommand",
	"LocalForward",
	"LogLevel",
	"LogVerbose",
	"MACs",
	"NoHostAuthenticationForLocalhost",
	"NumberOfPasswordPrompts",
	"PasswordAuthentication",
	"PermitLocalCommand",
	"PermitRemoteOpen",
	"PKCS11Provider",
	"Port",
	"PreferredAuthentications",
	"ProxyCommand",
	"ProxyJump",
	"ProxyUseFdpass",
	"PubkeyAcceptedAlgorithms",
	"PubkeyAuthentication",
	"RekeyLimit",
	"RemoteCommand",
	"RemoteForward",
	"RequestTTY",
	"RevokedHostKeys",
	"SecurityKeyProvider",
	"SendEnv",
	"ServerAliveCountMax",
	"ServerAliveInterval",
	"SessionType",
	"SetEnv",
	"StdinNull",
	"StreamLocalBindMask",
	"StreamLocalBindUnlink",
	"StrictHostKeyChecking",
	"SyslogFacility",
	"TCPKeepAlive",
	"Tunnel",
	"TunnelDevice",
	"UpdateHostKeys",
	"User",
	"UserKnownHostsFile",
	"VerifyHostKeyDNS",
	"VisualHostKey",
	"XAuthLocation",
}

// // getConfigOptions retrieves a sorted list of all the current config options
// // from the official source: https://man.openbsd.org/ssh_config and filtered
// // with "github.com/PuerkitoBio/goquery".
// // The result is sorted and therefore may be searched with sort.SearchStrings()
// func getConfigOptions() (opts []string, err error) {
// 	SSHConfigURL := "https://man.openbsd.org/ssh_config"

// 	resp, err := http.Get(SSHConfigURL)
// 	if err != nil {
// 		return opts, fmt.Errorf("getting %s: %w", SSHConfigURL, err)
// 	}
// 	defer resp.Body.Close()

// 	doc, err := goquery.NewDocumentFromReader(resp.Body)
// 	if err != nil {
// 		return opts, fmt.Errorf("parsing %s: %w", SSHConfigURL, err)
// 	}

// 	doc.Find("dt > a > code.Cm").Each(func(i int, c *goquery.Selection) {
// 		opts = append(opts, c.Text())
// 	})

// 	sort.Strings(opts)
// 	return opts, nil
// }

var configOptionsMap = map[string]string{}

func init() {
	for _, opt := range configOptions {
		configOptionsMap[strings.ToLower(opt)] = opt
	}
}

// GetCanonicalCase checks for the given key in the known ssh config keys
// and returns with proper casing if found, otherwise returns what was given.
func GetCanonicalCase(key string) string {
	if v, ok := configOptionsMap[strings.ToLower(key)]; ok {
		return v
	}

	return key
}
