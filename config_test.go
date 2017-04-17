package ssh_config

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func loadFile(t *testing.T, filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var files = []string{"testdata/config1", "testdata/config2"}

func TestLoadReader(t *testing.T) {
	for _, filename := range files {
		data := loadFile(t, filename)
		cfg, err := LoadReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		out := cfg.String()
		if out != string(data) {
			t.Errorf("out != data: out: %q\ndata: %q", out, string(data))
		}
	}
}
