# ssh_config

This is a Go parser for `ssh_config` files. Importantly, this parser attempts to
preserve comments, so you can manipulate a `ssh_config` file from a program, if
your heart wishes.

Example usage:

```go
f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
cfg, _ := ssh_config.LoadReader(f)
for _, host := range cfg.Hosts {
    fmt.Println("patterns:", host.Patterns)
    for _, node := range host.Nodes {
        fmt.Println(node.String())
    }
}

// Write the cfg back to disk:
fmt.Println(cfg.String())
```

This is very alpha software. In particular the most useful thing you want to do
with this is figure out the correct HostName and User for a particular host
pattern. There's no way to do this, currently.
