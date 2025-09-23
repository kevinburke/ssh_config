//go:build !linux

package ssh_config

var DefaultConfigFileFinders = []ConfigFileFinder{UserHomeConfigFileFinder}
