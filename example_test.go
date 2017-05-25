package ssh_config

import "fmt"

func ExampleHost_Matches() {
	pat, _ := NewPattern("test.*.example.com")
	host := &Host{Patterns: []*Pattern{pat}}
	fmt.Println(host.Matches("test.stage.example.com"))
	fmt.Println(host.Matches("othersubdomain.example.com"))
	// Output:
	// true
	// false
}
