package ssh_config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

type configFinder func() string

type UserSettings struct {
	systemConfig       *Config
	systemConfigFinder configFinder
	userConfig         *Config
	userConfigFinder   configFinder
	username           string
	loadConfigs        sync.Once
	onceErr            error
	IgnoreErrors       bool
}

func userConfigFinder() string {
	user, err := osuser.Current()
	var home string
	if err == nil {
		home = user.HomeDir
	} else {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".ssh", "config")
}

// DefaultUserSettings is the default UserSettings and is used by Get and
// GetStrict. It checks both $HOME/.ssh/config and /etc/ssh/ssh_config for
// keys, and it will return parse errors (if any).
var DefaultUserSettings = &UserSettings{
	IgnoreErrors:       false,
	systemConfigFinder: systemConfigFinder,
	userConfigFinder:   userConfigFinder,
}

func systemConfigFinder() string {
	return filepath.Join("/", "etc", "ssh", "ssh_config")
}

func findVal(c *Config, alias, key string) (string, error) {
	if c == nil {
		return "", nil
	}
	return c.Get(alias, key)
}

// Get finds the first value for key within a declaration that matches the
// alias. Get returns the empty string if no value was found, or if IgnoreErrors
// is false and we could not parse the configuration file. Use GetStrict to
// disambiguate the latter cases.
//
// The match for key is case insensitive.
//
// Get is a wrapper around DefaultUserSettings.Get.
func Get(alias, key string) string {
	return DefaultUserSettings.Get(alias, key)
}

// GetStrict finds the first value for key within a declaration that matches the
// alias. For more information on how patterns are matched, see the manpage for
// ssh_config.
//
// error will be non-nil if and only if a user's configuration file or the
// system configuration file could not be parsed, and u.IgnoreErrors is false.
//
// GetStrict is a wrapper around DefaultUserSettings.GetStrict.
func GetStrict(alias, key string) (string, error) {
	return DefaultUserSettings.GetStrict(alias, key)
}

// Get finds the first value for key within a declaration that matches the
// alias. Get returns the empty string if no value was found, or if IgnoreErrors
// is false and we could not parse the configuration file. Use GetStrict to
// disambiguate the latter cases.
//
// The match for key is case insensitive.
func (u *UserSettings) Get(alias, key string) string {
	val, err := u.GetStrict(alias, key)
	if err != nil {
		return ""
	}
	return val
}

// GetStrict finds the first value for key within a declaration that matches the
// alias. For more information on how patterns are matched, see the manpage for
// ssh_config.
//
// error will be non-nil if and only if a user's configuration file or the
// system configuration file could not be parsed, and u.IgnoreErrors is false.
func (u *UserSettings) GetStrict(alias, key string) (string, error) {
	u.loadConfigs.Do(func() {
		// can't parse user file, that's ok.
		var filename string
		if u.userConfigFinder == nil {
			filename = userConfigFinder()
		} else {
			filename = u.userConfigFinder()
		}
		var err error
		u.userConfig, err = parseFile(filename)
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
		if u.systemConfigFinder == nil {
			filename = systemConfigFinder()
		} else {
			filename = u.systemConfigFinder()
		}
		u.systemConfig, err = parseFile(filename)
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
	})
	if u.onceErr != nil && u.IgnoreErrors == false {
		return "", u.onceErr
	}
	val, err := findVal(u.userConfig, alias, key)
	if err != nil || val != "" {
		return val, err
	}
	return findVal(u.systemConfig, alias, key)
}

func parseFile(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Decode(f)
}

// Decode reads r into a Config, or returns an error if r could not be parsed as
// an SSH config file.
func Decode(r io.Reader) (c *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			err = errors.New(r.(string))
		}
	}()

	c = parseSSH(lexSSH(r))
	return c, err
}

// Config represents an SSH config file.
type Config struct {
	position Position
	// A list of hosts to match against. The file begins with an implicit
	// "Host *" declaration matching all hosts.
	Hosts []*Host
}

// Get finds the first value in the configuration that matches the alias and
// contains key. Get returns the empty string if no value was found, the Config
// contains an invalid conditional Include value.
//
// The match for key is case insensitive.
//
// Get is a wrapper around DefaultUserSettings.Get.
func (c *Config) Get(alias, key string) (string, error) {
	lowerKey := strings.ToLower(key)
	for _, host := range c.Hosts {
		if !host.Matches(alias) {
			continue
		}
		for _, node := range host.Nodes {
			switch t := node.(type) {
			case *Empty:
				continue
			case *KV:
				// "keys are case insensitive" per the spec
				lkey := strings.ToLower(t.Key)
				if lkey == "include" {
					panic("can't handle Include directives")
				}
				if lkey == "match" {
					panic("can't handle Match directives")
				}
				if lkey == lowerKey {
					return t.Value, nil
				}
			default:
				return "", fmt.Errorf("unknown Node type %v", t)
			}
		}
	}
	return "", nil
}

func (c *Config) String() string {
	var buf bytes.Buffer
	for i := range c.Hosts {
		buf.WriteString(c.Hosts[i].String())
	}
	return buf.String()
}

type Pattern struct {
	str   string
	regex *regexp.Regexp
}

func (p Pattern) String() string {
	return p.str
}

// Copied from regexp.go with * and ? removed.
var specialBytes = []byte(`\.+()|[]{}^$`)

func special(b byte) bool {
	return bytes.IndexByte(specialBytes, b) >= 0
}

// NewPattern creates a new Pattern for matching hosts.
func NewPattern(s string) (*Pattern, error) {
	// From the manpage:
	// A pattern consists of zero or more non-whitespace characters,
	// `*' (a wildcard that matches zero or more characters),
	// or `?' (a wildcard that matches exactly one character).
	// For example, to specify a set of declarations for any host in the
	// ".co.uk" set of domains, the following pattern could be used:
	//
	//		Host *.co.uk
	//
	// The following pattern would match any host in the 192.168.0.[0-9] network range:
	//
	//		Host 192.168.0.?
	var buf bytes.Buffer
	buf.WriteByte('^')
	for i := 0; i < len(s); i++ {
		// A byte loop is correct because all metacharacters are ASCII.
		switch b := s[i]; b {
		case '*':
			buf.WriteString(".*")
		case '?':
			buf.WriteString(".?")
		default:
			// borrowing from QuoteMeta here.
			if special(b) {
				buf.WriteByte('\\')
			}
			buf.WriteByte(b)
		}
	}
	buf.WriteByte('$')
	r, err := regexp.Compile(buf.String())
	if err != nil {
		return nil, err
	}
	return &Pattern{str: s, regex: r}, nil
}

type Host struct {
	// A list of host patterns that should match this host.
	Patterns []*Pattern
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
	// EOLComment is the comment (if any) terminating the Host line.
	EOLComment   string
	hasEquals    bool
	leadingSpace uint16 // TODO: handle spaces vs tabs here.
	// The file starts with an implicit "Host *" declaration.
	implicit bool
}

func (h *Host) Matches(alias string) bool {
	found := false
	for i := range h.Patterns {
		if h.Patterns[i].regex.MatchString(alias) {
			found = true
			break
		}
	}
	return found
}

func (h *Host) String() string {
	var buf bytes.Buffer
	if h.implicit == false {
		buf.WriteString(strings.Repeat(" ", int(h.leadingSpace)))
		buf.WriteString("Host")
		if h.hasEquals {
			buf.WriteString(" = ")
		} else {
			buf.WriteString(" ")
		}
		for i, pat := range h.Patterns {
			buf.WriteString(pat.str)
			if i < len(h.Patterns)-1 {
				buf.WriteString(" ")
			}
		}
		if h.EOLComment != "" {
			buf.WriteString(" #")
			buf.WriteString(h.EOLComment)
		}
		buf.WriteByte('\n')
	}
	for i := range h.Nodes {
		buf.WriteString(h.Nodes[i].String())
		buf.WriteByte('\n')
	}
	return buf.String()
}

type Node interface {
	Pos() Position
	String() string
}

type KV struct {
	Key          string
	Value        string
	Comment      string
	hasEquals    bool
	leadingSpace uint16 // Space before the key. TODO handle spaces vs tabs.
	position     Position
}

func (k *KV) Pos() Position {
	return k.position
}

func (k *KV) String() string {
	if k == nil {
		return ""
	}
	equals := " "
	if k.hasEquals {
		equals = " = "
	}
	line := fmt.Sprintf("%s%s%s%s", strings.Repeat(" ", int(k.leadingSpace)), k.Key, equals, k.Value)
	if k.Comment != "" {
		line += " #" + k.Comment
	}
	return line
}

type Empty struct {
	Comment      string
	leadingSpace uint16 // TODO handle spaces vs tabs.
	position     Position
}

func (e *Empty) Pos() Position {
	return e.position
}

func (e *Empty) String() string {
	if e == nil {
		return ""
	}
	if e.Comment == "" {
		return ""
	}
	return fmt.Sprintf("%s#%s", strings.Repeat(" ", int(e.leadingSpace)), e.Comment)
}

var matchAll *Pattern

func init() {
	var err error
	matchAll, err = NewPattern("*")
	if err != nil {
		panic(err)
	}
}

func newConfig() *Config {
	return &Config{
		Hosts: []*Host{
			&Host{implicit: true, Patterns: []*Pattern{matchAll}, Nodes: make([]Node, 0)},
		},
	}
}
