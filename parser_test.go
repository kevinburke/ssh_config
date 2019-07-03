package ssh_config

import (
	"errors"
	"testing"
)

type errReader struct {
}

func (b *errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("bad")
}

func TestIOError(t *testing.T) {
	buf := &errReader{}
	defer func() {
		recover()
	}()
	parseSSH(lexSSH(buf), false, 0)
}
