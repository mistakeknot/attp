package merkle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExcluderMatchesCanonicalPathAndBasename(t *testing.T) {
	ex, err := NewExcluder([]string{".env", "*.key", "secrets*", "# comment", ""})
	if err != nil {
		t.Fatalf("NewExcluder: %v", err)
	}
	cases := map[string]bool{
		".env":                true,
		"sub/dir/.env":        true, // basename match, as the tree builder applies it
		"keys/id_ed25519.key": true,
		"secrets.yaml":        true,
		"main.go":             false,
		"docs/environment.md": false,
		"sub\\windows\\.env":  true, // any separator canonicalizes
	}
	for path, want := range cases {
		if got := ex.Excluded(path); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestExcluderForDirReadsAttpIgnore(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".attpignore"), []byte("# local rules\n.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex, err := NewExcluderForDir(root, []string{"*.pem"})
	if err != nil {
		t.Fatalf("NewExcluderForDir: %v", err)
	}
	if !ex.Excluded(".env") {
		t.Error(".env from .attpignore should be excluded")
	}
	if !ex.Excluded("cert.pem") {
		t.Error("*.pem from explicit patterns should be excluded")
	}
	if ex.Excluded("README.md") {
		t.Error("README.md should not be excluded")
	}
}

func TestNilExcluderExcludesNothing(t *testing.T) {
	var ex *Excluder
	if ex.Excluded(".env") {
		t.Error("nil excluder must exclude nothing")
	}
}

// The tree and the excluder must agree: a file the excluder withholds is a
// file the tree never hashed.
func TestBuildFromDirAgreesWithExcluder(t *testing.T) {
	root := t.TempDir()
	must := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(".attpignore", ".env\n")
	must(".env", "SECRET=1\n")
	must("main.go", "package main\n")

	tree, err := BuildFromDir(root, nil)
	if err != nil {
		t.Fatalf("BuildFromDir: %v", err)
	}
	ex, err := NewExcluderForDir(root, nil)
	if err != nil {
		t.Fatalf("NewExcluderForDir: %v", err)
	}
	for _, leaf := range tree.Leaves {
		if ex.Excluded(leaf.Path) {
			t.Errorf("tree hashed %q, which the excluder withholds", leaf.Path)
		}
	}
	if _, err := InclusionProof(tree, "main.go"); err != nil {
		t.Errorf("main.go should be in the tree: %v", err)
	}
	if _, err := InclusionProof(tree, ".env"); err == nil {
		t.Error(".env must not be in the tree")
	}
}
