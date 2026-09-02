package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mistakeknot/attp/pkg/merkle"
	"github.com/mistakeknot/attp/pkg/token"
)

func TestSelectPayloadPathsWithholdsExcludedFiles(t *testing.T) {
	ex, err := merkle.NewExcluder([]string{".env", "*.key"})
	if err != nil {
		t.Fatal(err)
	}
	shipped, withheld := selectPayloadPaths([]string{".env", "main.go", "keys/id.key", "docs/README.md"}, ex)
	wantShipped := []string{"main.go", "docs/README.md"}
	wantWithheld := []string{".env", "keys/id.key"}
	if !equalStrings(shipped, wantShipped) {
		t.Errorf("shipped = %v, want %v", shipped, wantShipped)
	}
	if !equalStrings(withheld, wantWithheld) {
		t.Errorf("withheld = %v, want %v", withheld, wantWithheld)
	}
}

// End to end: a dirty .env in a repo with the default .attpignore is listed
// under excluded_paths and never appears as a payload. This is the property
// the README's headline claim ("prove what you did NOT send") rests on.
func TestPackNeverShipsExcludedContent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	repo := t.TempDir()
	restore := chdir(t, repo)
	defer restore()

	gitRun(t, "init", "-q", "-b", "main")
	gitRun(t, "config", "user.email", "test@example.invalid")
	gitRun(t, "config", "user.name", "attp test")
	writeFile(t, "README.md", "hello\n")
	gitRun(t, "add", "README.md")
	gitRun(t, "commit", "-q", "-m", "init")

	// Keys, config, and the default .attpignore (which lists .env).
	if err := cmdInit(); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	writeFile(t, ".env", "SECRET=do-not-ship\n")
	writeFile(t, "feature.go", "package feature\n")

	if err := cmdPack(); err != nil {
		t.Fatalf("cmdPack: %v", err)
	}
	data, err := os.ReadFile("attp-token.json")
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	var tok token.Token
	if err := json.Unmarshal(data, &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}

	if !contains(tok.Sensitivity.ExcludedPaths, ".env") {
		t.Errorf("excluded_paths = %v, want .env listed", tok.Sensitivity.ExcludedPaths)
	}
	var shippedPaths []string
	for _, p := range tok.Payloads {
		shippedPaths = append(shippedPaths, p.Path)
		if p.Path == ".env" {
			t.Fatalf("token carries .env as a payload: %q", p.Content)
		}
	}
	if !contains(shippedPaths, "feature.go") {
		t.Errorf("payloads = %v, want feature.go shipped", shippedPaths)
	}
	if bytes.Contains(data, []byte("do-not-ship")) {
		t.Fatal("token bytes contain the excluded file's content")
	}
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() { _ = os.Chdir(prev) }
}

func gitRun(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
