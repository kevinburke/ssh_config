# ssh_config

This is a Go parser for `ssh_config` files. Importantly, this parser attempts
to preserve comments in a given file, so you can manipulate a `ssh_config` file
from a program, if your heart desires.

Example usage:

```go
f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
cfg, _ := ssh_config.Decode(f)
for _, host := range cfg.Hosts {
    fmt.Println("patterns:", host.Patterns)
    for _, node := range host.Nodes {
        fmt.Println(node.String())
    }
}

// Write the cfg back to disk:
fmt.Println(cfg.String())
```

The `ssh_config` program will attempt to read values from `$HOME/.ssh/config`,
falling back to `/etc/ssh/ssh_config`.

```go
port := ssh_config.Get("myhost", "Port")
```

## Donating

Donations free up time to make improvements to the library, and respond to
bug reports. You can send donations via Paypal's "Send Money" feature to
kev@inburke.com. Donations are not tax deductible in the USA.
