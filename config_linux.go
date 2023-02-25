package ssh_config

import "path/filepath"

// SystemConfigFileFinder return ~/etc/ssh/ssh_config on linux os,
func SystemConfigFileFinder() (string, error) {
	return filepath.Join("/", "etc", "ssh", "ssh_config"), nil
}

var DefaultConfigFileFinders = []ConfigFileFinder{UserHomeConfigFileFinder, SystemConfigFileFinder}
