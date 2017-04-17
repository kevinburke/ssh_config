package ssh_config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

func User(hostname string) string {
	return ""
}

type ConfigFinder struct {
	IgnoreSystemConfig bool
	IgnoreUserConfig   bool
}

func (c *ConfigFinder) User(hostname string) string {
	return ""
}

var DefaultFinder = &ConfigFinder{IgnoreSystemConfig: false, IgnoreUserConfig: false}

func parseFile(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadReader(f)
}

func LoadReader(r io.Reader) (c *Config, err error) {
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
	Hosts    []*Host
}

func (c *Config) String() string {
	var buf bytes.Buffer
	for i := range c.Hosts {
		buf.WriteString(c.Hosts[i].String())
	}
	return buf.String()
}

type Host struct {
	// A list of host patterns that should match this host.
	Patterns []string
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
	// EOLComment is the comment (if any) terminating the Host line.
	EOLComment   string
	leadingSpace uint16 // TODO: handle spaces vs tabs here.
	// The file starts with an implicit "Host *" declaration.
	implicit bool
}

func (h *Host) String() string {
	var buf bytes.Buffer
	if h.implicit == false {
		buf.WriteString(strings.Repeat(" ", int(h.leadingSpace)))
		buf.WriteString("Host ")
		buf.WriteString(strings.Join(h.Patterns, " "))
		if h.EOLComment != "" {
			buf.WriteString(" #")
			buf.WriteString(h.EOLComment)
		}
		buf.WriteByte('\n')
	}
	for i := range h.Nodes {
		//fmt.Printf("%q\n", h.Nodes[i].String())
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
	line := fmt.Sprintf("%s%s %s", strings.Repeat(" ", int(k.leadingSpace)), k.Key, k.Value)
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

func newConfig() *Config {
	return &Config{
		Hosts: []*Host{
			&Host{implicit: true, Patterns: []string{"*"}, Nodes: make([]Node, 0)},
		},
	}
}
