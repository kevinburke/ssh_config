package ssh_config_test

import (
	"fmt"
	"path/filepath"
	"strings"
)
import "github.com/kevinburke/ssh_config"

func ExampleHost_Matches() {
	pat, _ := ssh_config.NewPattern("test.*.example.com")
	host := &ssh_config.Host{Patterns: []*ssh_config.Pattern{pat}}
	fmt.Println(host.Matches("test.stage.example.com"))
	fmt.Println(host.Matches("othersubdomain.example.com"))
	// Output:
	// true
	// false
}

func ExamplePattern() {
	pat, _ := ssh_config.NewPattern("*")
	host := &ssh_config.Host{Patterns: []*ssh_config.Pattern{pat}}
	fmt.Println(host.Matches("test.stage.example.com"))
	fmt.Println(host.Matches("othersubdomain.any.any"))
	// Output:
	// true
	// true
}

func ExampleDecode() {
	var config = `
Host *.example.com
  Compression yes
`

	cfg, _ := ssh_config.Decode(strings.NewReader(config))
	val, _ := cfg.Get("test.example.com", "Compression")
	fmt.Println(val)
	// Output: yes
}

func ExampleDefault() {
	fmt.Println(ssh_config.Default("Port"))
	fmt.Println(ssh_config.Default("UnknownVar"))
	// Output:
	// 22
	//
}

func ExampleConfigFileFinder() {
	// This can be used to test SSH config parsing.
	u := ssh_config.UserSettings{}
	u.WithConfigLocations(func() (string, error) {
		return filepath.Join("testdata", "test_config"), nil
	})

	fmt.Println(u.Get("example.com", "HostName"))
	// Output:
	// wap.example.org
	//
}
