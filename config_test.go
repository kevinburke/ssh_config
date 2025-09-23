package ssh_config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func loadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var files = []string{
	"testdata/config1",
	"testdata/config2",
	"testdata/eol-comments",
}

func TestDecode(t *testing.T) {
	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			data := loadFile(t, filename)
			cfg, err := Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			out := cfg.String()
			if out != string(data) {
				t.Errorf("%s out != data: got:\n%s\nwant:\n%s\n", filename, out, string(data))
			}
		})
	}
}

func nullConfigFinder() string {
	return ""
}

func TestUserSettings(t *testing.T) {

	assertFileFinder := func(t *testing.T, target *UserSettings, idx int, expected string) {
		file, _ := target.configFiles[idx]()
		if file != expected {
			t.Errorf("set configuration was not previously used finder function; idx: %d", idx)
		}
	}

	finderFncA := func() (string, error) { return "expected_file_A", nil }
	finderFncB := func() (string, error) { return "expected_file_B", nil }
	finderFncC := func() (string, error) { return "expected_file_C", nil }

	testConfigFinder := func(filename string) ConfigFileFinder {
		return func() (string, error) { return filename, nil }
	}

	assert := func(t *testing.T, target *UserSettings, host, key, expect string) {
		val, err := target.GetStrict(host, key)
		if err != nil {
			t.Fatal(err)
		}

		if val != expect {
			t.Errorf("wrong port: got %q want %s", val, expect)
		}
	}

	asserter := func(target *UserSettings, host, key, expect string) func(t *testing.T) {
		return func(t *testing.T) { assert(t, target, host, key, expect) }
	}

	t.Run("WithConfigLocations", func(t *testing.T) {

		obj := &UserSettings{}

		configuredObject := obj.WithConfigLocations(finderFncA, finderFncB)

		if configuredObject != obj {
			t.Errorf("the same instance back, got %v", configuredObject)
		}

		if len(obj.configFiles) != 2 {
			t.Errorf("number of set file finder function does not match; expected 2 got : %d", len(obj.configFiles))
		}

		assertFileFinder(t, obj, 0, "expected_file_A")
		assertFileFinder(t, obj, 1, "expected_file_B")
	})

	t.Run("AddConfigLocations", func(t *testing.T) {

		obj := &UserSettings{configFiles: []ConfigFileFinder{finderFncA}}

		if len(obj.configFiles) != 1 {
			t.Errorf("number of set file finder function does not match; expected 1 got : %d", len(obj.configFiles))
		}

		configuredObject := obj.AddConfigLocations(finderFncB, finderFncC)

		if configuredObject != obj {
			t.Errorf("the same instance back, got %v", configuredObject)
		}
		if len(obj.configFiles) != 3 {
			t.Errorf("number of set file finder function does not match; expected 1 got : %d", len(obj.configFiles))
		}

		assertFileFinder(t, obj, 0, "expected_file_A")
		assertFileFinder(t, obj, 1, "expected_file_B")
		assertFileFinder(t, obj, 2, "expected_file_C")
	})

	t.Run("Get", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val := us.Get("wap", "User")
		if val != "root" {
			t.Errorf("expected to find User root, got %q", val)
		}
	})

	t.Run("GetWithDefault", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val, err := us.GetStrict("wap", "PasswordAuthentication")
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if val != "yes" {
			t.Errorf("expected to get PasswordAuthentication yes, got %q", val)
		}
	})

	t.Run("GetAllWithDefault", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val, err := us.GetAllStrict("wap", "PasswordAuthentication")
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if len(val) != 1 || val[0] != "yes" {
			t.Errorf("expected to get PasswordAuthentication yes, got %q", val)
		}
	})

	t.Run("GetIdentities", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/identities")},
		}

		val, err := us.GetAllStrict("hasidentity", "IdentityFile")
		if err != nil {
			t.Errorf("expected nil err, got %v", err)
		}
		if len(val) != 1 || val[0] != "file1" {
			t.Errorf(`expected ["file1"], got %v`, val)
		}

		val, err = us.GetAllStrict("has2identity", "IdentityFile")
		if err != nil {
			t.Errorf("expected nil err, got %v", err)
		}
		if len(val) != 2 || val[0] != "f1" || val[1] != "f2" {
			t.Errorf(`expected [\"f1\", \"f2\"], got %v`, val)
		}

		val, err = us.GetAllStrict("randomhost", "IdentityFile")
		if err != nil {
			t.Errorf("expected nil err, got %v", err)
		}
		if len(val) != len(defaultProtocol2Identities) {
			// TODO: return the right values here.
			log.Printf("expected defaults, got %v", val)
		} else {
			for i, v := range defaultProtocol2Identities {
				if val[i] != v {
					t.Errorf("invalid %d in val, expected %s got %s", i, v, val[i])
				}
			}
		}

		val, err = us.GetAllStrict("protocol1", "IdentityFile")
		if err != nil {
			t.Errorf("expected nil err, got %v", err)
		}
		if len(val) != 1 || val[0] != "~/.ssh/identity" {
			t.Errorf("expected [\"~/.ssh/identity\"], got %v", val)
		}
	})

	t.Run("GetInvalidPort", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/invalid-port")},
		}

		val, err := us.GetStrict("test.test", "Port")
		if err == nil {
			t.Fatalf("expected non-nil err, got nil")
		}
		if val != "" {
			t.Errorf("expected to get '' for val, got %q", val)
		}
		if err.Error() != `ssh_config: strconv.ParseUint: parsing "notanumber": invalid syntax` {
			t.Errorf("wrong error: got %v", err)
		}
	})

	t.Run("GetNotFoundNoDefault", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val, err := us.GetStrict("wap", "CanonicalDomains")
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if val != "" {
			t.Errorf("expected to get CanonicalDomains '', got %q", val)
		}
	})

	t.Run("GetAllNotFoundNoDefault", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val, err := us.GetAllStrict("wap", "CanonicalDomains")
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if len(val) != 0 {
			t.Errorf("expected to get CanonicalDomains '', got %q", val)
		}
	})

	t.Run("GetWildcard", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config3")},
		}

		val := us.Get("bastion.stage.i.us.example.net", "Port")
		if val != "22" {
			t.Errorf("expected to find Port 22, got %q", val)
		}

		val = us.Get("bastion.net", "Port")
		if val != "25" {
			t.Errorf("expected to find Port 24, got %q", val)
		}

		val = us.Get("10.2.3.4", "Port")
		if val != "23" {
			t.Errorf("expected to find Port 23, got %q", val)
		}
		val = us.Get("101.2.3.4", "Port")
		if val != "25" {
			t.Errorf("expected to find Port 24, got %q", val)
		}
		val = us.Get("20.20.20.4", "Port")
		if val != "24" {
			t.Errorf("expected to find Port 24, got %q", val)
		}
		val = us.Get("20.20.20.20", "Port")
		if val != "25" {
			t.Errorf("expected to find Port 25, got %q", val)
		}
	})

	t.Run("GetExtraSpaces", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/extraspace")},
		}

		val := us.Get("test.test", "Port")
		if val != "1234" {
			t.Errorf("expected to find Port 1234, got %q", val)
		}
	})

	t.Run("GetCaseInsensitive", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config1")},
		}

		val := us.Get("wap", "uSER")
		if val != "root" {
			t.Errorf("expected to find User root, got %q", val)
		}
	})

	t.Run("GetEmpty", func(t *testing.T) {
		us := &UserSettings{}

		val, err := us.GetStrict("wap", "User")
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
		if val != "" {
			t.Errorf("expected to get empty string, got %q", val)
		}
	})

	t.Run("GetEqsign", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/eqsign")},
		}

		val := us.Get("test.test", "Port")
		if val != "1234" {
			t.Errorf("expected to find Port 1234, got %q", val)
		}
		val = us.Get("test.test", "Port2")
		if val != "5678" {
			t.Errorf("expected to find Port2 5678, got %q", val)
		}
	})

	t.Run("MatchUnsupported", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/match-directive")},
		}

		_, err := us.GetStrict("test.test", "Port")
		if err == nil {
			t.Fatal("expected Match directive to error, didn't")
		}
		if !strings.Contains(err.Error(), "ssh_config: Match directive parsing is unsupported") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("IndexInRange", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config4")},
		}

		user, err := us.GetStrict("wap", "User")
		if err != nil {
			t.Fatal(err)
		}
		if user != "root" {
			t.Errorf("expected User to be %q, got %q", "root", user)
		}
	})

	t.Run("DosLinesEndingsDecode", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/dos-lines")},
		}

		user, err := us.GetStrict("wap", "User")
		if err != nil {
			t.Fatal(err)
		}

		if user != "root" {
			t.Errorf("expected User to be %q, got %q", "root", user)
		}

		host, err := us.GetStrict("wap2", "HostName")
		if err != nil {
			t.Fatal(err)
		}

		if host != "8.8.8.8" {
			t.Errorf("expected HostName to be %q, got %q", "8.8.8.8", host)
		}
	})

	t.Run("NoTrailingNewline", func(t *testing.T) {
		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/config-no-ending-newline")},
		}

		port, err := us.GetStrict("example", "Port")
		if err != nil {
			t.Fatal(err)
		}

		if port != "4242" {
			t.Errorf("wrong port: got %q want 4242", port)
		}
	})

	t.Run("fallback resolving", func(t *testing.T) {

		finderUser := testConfigFinder("testdata/test_config_fallback_user")
		finderLayer2 := testConfigFinder("testdata/test_config_fallback_layer2")
		finderLayer1 := testConfigFinder("testdata/test_config_fallback_layer1")
		finderBase := testConfigFinder("testdata/test_config_fallback_base")

		t.Run("user", func(t *testing.T) {
			us := &UserSettings{
				configFiles: []ConfigFileFinder{finderUser, finderLayer2, finderLayer1, finderBase},
			}

			t.Run("port custom", asserter(us, "custom", "Port", "2300"))
			t.Run("port any", asserter(us, "some-host", "Port", "23"))
			t.Run("user custom", asserter(us, "custom", "User", "pete"))
			t.Run("user any", asserter(us, "some-host", "User", "foo"))
		})

		t.Run("layer2", func(t *testing.T) {
			us := &UserSettings{
				configFiles: []ConfigFileFinder{finderLayer2, finderLayer1, finderBase},
			}

			t.Run("port custom", asserter(us, "custom", "Port", "2300"))
			t.Run("port any", asserter(us, "some-host", "Port", "23"))
			t.Run("user custom", asserter(us, "custom", "User", "root"))
			t.Run("user any", asserter(us, "some-host", "User", "foo"))
		})

		t.Run("layer1", func(t *testing.T) {
			us := &UserSettings{
				configFiles: []ConfigFileFinder{finderLayer1, finderBase},
			}

			t.Run("port custom", asserter(us, "custom", "Port", "23"))
			t.Run("port any", asserter(us, "some-host", "Port", "23"))
			t.Run("user custom", asserter(us, "custom", "User", "bar"))
			t.Run("user any", asserter(us, "some-host", "User", "foo"))
		})

		t.Run("base", func(t *testing.T) {
			us := &UserSettings{
				configFiles: []ConfigFileFinder{finderBase},
			}

			t.Run("port custom", asserter(us, "custom", "Port", "22"))
			t.Run("port any", asserter(us, "some-host", "Port", "22"))
			t.Run("user custom", asserter(us, "custom", "User", "foo"))
			t.Run("user any", asserter(us, "some-host", "User", "foo"))
		})
	})

	t.Run("Include basic", func(t *testing.T) {

		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/include-basic/config")},
		}

		assert(t, us, "kevinburke.ssh_config.test.example.com", "Port", "4567")
		assert(t, us, "kevinburke.ssh_config.test.example.com", "User", "foobar")
	})

	t.Run("Include recursive", func(t *testing.T) {

		us := &UserSettings{
			configFiles: []ConfigFileFinder{testConfigFinder("testdata/include-recursive/config")},
		}

		val, err := us.GetStrict("kevinburke.ssh_config.test.example.com", "Port")
		if err != ErrDepthExceeded {
			t.Errorf("Recursive include: expected ErrDepthExceeded, got %v", err)
		}
		if val != "" {
			t.Errorf("non-empty string value %s", val)
		}
	})

	t.Run("IncludeString", func(t *testing.T) {
		data, err := os.ReadFile("testdata/include-basic/config")
		if err != nil {
			log.Fatal(err)
		}
		c, err := Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		s := c.String()
		if s != string(data) {
			t.Errorf("mismatch: got %q\nwant %q", s, string(data))
		}
	})
}

//TODO: this is not the way to to this!!!
//
//func TestIncludeSystem(t *testing.T) {
//	if testing.Short() {
//		t.Skip("skipping fs write in short mode")
//	}
//	testPath := filepath.Join("/", "etc", "ssh", "kevinburke-ssh-config-test-file")
//	err := os.WriteFile(testPath, includeFile, 0644)
//	if err != nil {
//		t.Skipf("couldn't write SSH config file: %v", err.Error())
//	}
//	defer os.Remove(testPath)
//	us := &UserSettings{
//		systemConfigFinder: testConfigFinder("testdata/include"),
//	}
//	val := us.Get("kevinburke.ssh_config.test.example.com", "Port")
//	if val != "4567" {
//		t.Errorf("expected to find Port=4567 in included file, got %q", val)
//	}
//}

func TestUserHomeConfigFileFinder(t *testing.T) {

	userHome, err := UserHomeConfigFileFinder()

	if err != nil {
		t.Fatalf("no error expected; got %v", err)
	}

	if userHome == "" {
		t.Errorf("expected a return value; got %q", userHome)
	}

	if !strings.HasSuffix(userHome, "/.ssh/config") {
		t.Errorf("expected return value to match default windows folders; got %q", userHome)
	}

}

var matchTests = []struct {
	in    []string
	alias string
	want  bool
}{
	{[]string{"*"}, "any.test", true},
	{[]string{"a", "b", "*", "c"}, "any.test", true},
	{[]string{"a", "b", "c"}, "any.test", false},
	{[]string{"any.test"}, "any1test", false},
	{[]string{"192.168.0.?"}, "192.168.0.1", true},
	{[]string{"192.168.0.?"}, "192.168.0.10", false},
	{[]string{"*.co.uk"}, "bbc.co.uk", true},
	{[]string{"*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.*.co.uk"}, "bbc.co.uk", false},
	{[]string{"*.*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.example.com", "!*.dialup.example.com", "foo.dialup.example.com"}, "foo.dialup.example.com", false},
	{[]string{"test.*", "!test.host"}, "test.host", false},
}

func TestMatches(t *testing.T) {
	for _, tt := range matchTests {
		patterns := make([]*Pattern, len(tt.in))
		for i := range tt.in {
			pat, err := NewPattern(tt.in[i])
			if err != nil {
				t.Fatalf("error compiling pattern %s: %v", tt.in[i], err)
			}
			patterns[i] = pat
		}
		host := &Host{
			Patterns: patterns,
		}
		got := host.Matches(tt.alias)
		if got != tt.want {
			t.Errorf("host(%q).Matches(%q): got %v, want %v", tt.in, tt.alias, got, tt.want)
		}
	}
}
