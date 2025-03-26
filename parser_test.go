package ssh_config

import (
	"errors"
	"strings"
	"testing"
)

type errReader struct {
}

func (b *errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error occurred")
}

func TestIOError(t *testing.T) {
	buf := &errReader{}
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("expected non-nil err, got nil")
	}
	if err.Error() != "read error occurred" {
		t.Errorf("expected read error msg, got %v", err)
	}
}

func TestParseMatchHostString(t *testing.T) {
	var config = `
Match Host *.example.com
  Compression yes
  HostName test.example.com
  Port 2222
  User hi_there
`

	cfg, err := Decode(strings.NewReader(config))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	val, err := cfg.Get("dev.example.com", "Port")
	if err != nil {
		t.Errorf("failed to get Port: %v", err)
	}
	if val != "2222" {
		t.Errorf("expected Port=2222, got %q", val)
	}

	val, err = cfg.Get("uat.example.com", "User")
	if err != nil {
		t.Errorf("failed to get User: %v", err)
	}
	if val != "hi_there" {
		t.Errorf("expected User=hi_there, got %q", val)
	}

	val, err = cfg.Get("prod.example.com", "HostName")
	if err != nil {
		t.Errorf("failed to get User: %v", err)
	}
	if val != "test.example.com" {
		t.Errorf("expected HostName=test.example.com, got %q", val)
	}
}

func TestMatchDirective(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		alias    string
		key      string
		wantVal  string
		wantErr  bool
		errMatch string
	}{
		{
			name: "basic match host",
			config: `Match Host *.example.com
    Port 2222`,
			alias:   "test.example.com",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name: "match host with negation",
			config: `Match Host *.example.com !*.test.example.com
    Port 2222`,
			alias:   "dev.example.com",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name: "match host with negation - negated match",
			config: `Match Host *.example.com !*.test.example.com
    Port 2222`,
			alias:   "dev.test.example.com",
			key:     "Port",
			wantVal: "",
		},
		{
			name: "match host with comment",
			config: `Match Host *.example.com  # Production servers
    Port 2222`,
			alias:   "test.example.com",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name: "match without host criterion",
			config: `Match User admin
    Port 2222`,
			alias:    "test.example.com",
			key:      "Port",
			wantErr:  true,
			errMatch: "Only Match Host is currently supported",
		},
		{
			name: "match without criterion",
			config: `Match
    Port 2222`,
			alias:    "test.example.com",
			key:      "Port",
			wantErr:  true,
			errMatch: "Match directive requires at least one criterion",
		},
		{
			name: "match host with equals",
			config: `Match Host = *.example.com
    Port 2222`,
			alias:   "test.example.com",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name: "match host with multiple patterns",
			config: `Match Host *.example.com *.example.org
    Port 2222`,
			alias:   "test.example.org",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name: "match host with identity file",
			config: `Match Host *.prod.example.com
    IdentityFile ~/.ssh/prod_key`,
			alias:   "app.prod.example.com",
			key:     "IdentityFile",
			wantVal: "~/.ssh/prod_key",
		},
		{
			name: "match host with multiple identity files",
			config: `Match Host *.prod.example.com
    IdentityFile ~/.ssh/prod_key1
    IdentityFile ~/.ssh/prod_key2`,
			alias:   "app.prod.example.com",
			key:     "IdentityFile",
			wantVal: "~/.ssh/prod_key1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Decode(strings.NewReader(tt.config))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMatch)
				} else if !strings.Contains(err.Error(), tt.errMatch) {
					t.Errorf("expected error containing %q, got %v", tt.errMatch, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := cfg.Get(tt.alias, tt.key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantVal {
				t.Errorf("Get(%q, %q) = %q, want %q", tt.alias, tt.key, got, tt.wantVal)
			}
		})
	}
}

func TestMatchHostFile(t *testing.T) {
	tests := []struct {
		name    string
		alias   string
		key     string
		wantVal string
	}{
		{
			name:    "production server match",
			alias:   "prod.example.com",
			key:     "Port",
			wantVal: "2222",
		},
		{
			name:    "test server no match",
			alias:   "dev.test.example.com",
			key:     "Port",
			wantVal: "22", // Falls through to Host *.example.com
		},
		{
			name:    "ci server match",
			alias:   "build.company.com",
			key:     "Port",
			wantVal: "3333",
		},
		{
			name:    "deploy server match",
			alias:   "deploy.company.com",
			key:     "Port",
			wantVal: "3333",
		},
		{
			name:    "production server user",
			alias:   "prod.example.com",
			key:     "User",
			wantVal: "admin",
		},
		{
			name:    "test server user",
			alias:   "dev.test.example.com",
			key:     "User",
			wantVal: "developer", // Falls through to Host *.example.com
		},
		{
			name:    "production server identity file",
			alias:   "prod.example.com",
			key:     "IdentityFile",
			wantVal: "~/.ssh/prod_key",
		},
		{
			name:    "test server identity file",
			alias:   "dev.test.example.com",
			key:     "IdentityFile",
			wantVal: "~/.ssh/dev_key", // Falls through to Host *.example.com
		},
	}

	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-host"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := us.Get(tt.alias, tt.key)
			if got != tt.wantVal {
				t.Errorf("Get(%q, %q) = %q, want %q", tt.alias, tt.key, got, tt.wantVal)
			}
		})
	}

	// Test GetAll for multiple IdentityFile values
	t.Run("ci server multiple identity files", func(t *testing.T) {
		got := us.GetAll("build.company.com", "IdentityFile")
		want := []string{"~/.ssh/ci_key1", "~/.ssh/ci_key2"}
		if len(got) != len(want) {
			t.Errorf("GetAll(%q, %q) returned %d values, want %d", "build.company.com", "IdentityFile", len(got), len(want))
		}
		for i, w := range want {
			if i >= len(got) {
				t.Errorf("GetAll missing value at index %d, want %q", i, w)
				continue
			}
			if got[i] != w {
				t.Errorf("GetAll[%d] = %q, want %q", i, got[i], w)
			}
		}
	})
}

func TestMatchDirectiveGetAll(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		alias    string
		key      string
		wantVals []string
		wantErr  bool
		errMatch string
	}{
		{
			name: "match host with multiple identity files",
			config: `Match Host *.prod.example.com
    IdentityFile ~/.ssh/prod_key1
    IdentityFile ~/.ssh/prod_key2`,
			alias:    "app.prod.example.com",
			key:      "IdentityFile",
			wantVals: []string{"~/.ssh/prod_key1", "~/.ssh/prod_key2"},
		},
		{
			name: "match host with single identity file",
			config: `Match Host *.prod.example.com
    IdentityFile ~/.ssh/prod_key`,
			alias:    "app.prod.example.com",
			key:      "IdentityFile",
			wantVals: []string{"~/.ssh/prod_key"},
		},
		{
			name: "match host with identity files and negation",
			config: `Match Host *.example.com !*.test.example.com
    IdentityFile ~/.ssh/prod_key1
    IdentityFile ~/.ssh/prod_key2`,
			alias:    "dev.test.example.com",
			key:      "IdentityFile",
			wantVals: []string{}, // Should not match due to negation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Decode(strings.NewReader(tt.config))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMatch)
				} else if !strings.Contains(err.Error(), tt.errMatch) {
					t.Errorf("expected error containing %q, got %v", tt.errMatch, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := cfg.GetAll(tt.alias, tt.key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.wantVals) {
				t.Errorf("GetAll(%q, %q) returned %d values, want %d", tt.alias, tt.key, len(got), len(tt.wantVals))
			}
			for i, want := range tt.wantVals {
				if i >= len(got) {
					t.Errorf("GetAll(%q, %q) missing value at index %d, want %q", tt.alias, tt.key, i, want)
					continue
				}
				if got[i] != want {
					t.Errorf("GetAll(%q, %q)[%d] = %q, want %q", tt.alias, tt.key, i, got[i], want)
				}
			}
		})
	}
}
