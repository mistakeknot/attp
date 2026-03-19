package merkle

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

func makeEntry(path string, content string) Entry {
	return Entry{
		Path:        canonicalPath(path),
		ContentHash: blake3.Sum256([]byte(content)),
	}
}

func TestBuildFromEntries_Deterministic(t *testing.T) {
	entries := []Entry{
		makeEntry("src/main.go", "package main"),
		makeEntry("src/util.go", "package util"),
		makeEntry("README.md", "# Hello"),
	}

	tree1 := BuildFromEntries(entries)
	tree2 := BuildFromEntries(entries)

	if tree1.Root != tree2.Root {
		t.Fatal("tree root is not deterministic")
	}
	if tree1.Root == EmptyRoot {
		t.Fatal("non-empty tree should not have empty root")
	}
}

func TestBuildFromEntries_OrderIndependent(t *testing.T) {
	entries1 := []Entry{
		makeEntry("b.go", "b"),
		makeEntry("a.go", "a"),
		makeEntry("c.go", "c"),
	}
	entries2 := []Entry{
		makeEntry("c.go", "c"),
		makeEntry("a.go", "a"),
		makeEntry("b.go", "b"),
	}

	tree1 := BuildFromEntries(entries1)
	tree2 := BuildFromEntries(entries2)

	if tree1.Root != tree2.Root {
		t.Fatal("tree root should be order-independent (entries are sorted internally)")
	}
}

func TestBuildFromEntries_EmptyTree(t *testing.T) {
	tree := BuildFromEntries(nil)
	if tree.Root != EmptyRoot {
		t.Fatalf("empty tree root = %x, want %x", tree.Root, EmptyRoot)
	}
}

func TestBuildFromEntries_SingleEntry(t *testing.T) {
	entries := []Entry{makeEntry("only.txt", "only content")}
	tree := BuildFromEntries(entries)

	if tree.Root == EmptyRoot {
		t.Fatal("single-entry tree should not have empty root")
	}

	// For a single entry with n=1, the leaf is placed at nodes[1] and
	// the loop doesn't execute, so root = leaf hash directly.
	expected := entries[0].LeafHash()
	if tree.Root != expected {
		t.Fatalf("single-entry root = %x, want %x", tree.Root, expected)
	}
}

func TestInclusionProof_Valid(t *testing.T) {
	entries := []Entry{
		makeEntry("a.go", "aaa"),
		makeEntry("b.go", "bbb"),
		makeEntry("c.go", "ccc"),
		makeEntry("d.go", "ddd"),
	}
	tree := BuildFromEntries(entries)

	for _, e := range tree.Leaves {
		proof, err := InclusionProof(tree, e.Path)
		if err != nil {
			t.Fatalf("InclusionProof(%q): %v", e.Path, err)
		}
		if !VerifyInclusion(tree.Root, e.Path, e.ContentHash, proof) {
			t.Fatalf("VerifyInclusion failed for %q", e.Path)
		}
	}
}

func TestInclusionProof_RejectUnknown(t *testing.T) {
	entries := []Entry{
		makeEntry("a.go", "aaa"),
		makeEntry("b.go", "bbb"),
	}
	tree := BuildFromEntries(entries)

	_, err := InclusionProof(tree, "unknown.go")
	if err == nil {
		t.Fatal("expected error for unknown path")
	}
}

func TestInclusionProof_RejectWrongContent(t *testing.T) {
	entries := []Entry{
		makeEntry("a.go", "aaa"),
		makeEntry("b.go", "bbb"),
	}
	tree := BuildFromEntries(entries)

	proof, err := InclusionProof(tree, "a.go")
	if err != nil {
		t.Fatal(err)
	}

	wrongHash := blake3.Sum256([]byte("wrong content"))
	if VerifyInclusion(tree.Root, "a.go", wrongHash, proof) {
		t.Fatal("verification should fail with wrong content hash")
	}
}

func TestExclusionAttestation_SignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	tree := BuildFromEntries([]Entry{makeEntry("a.go", "aaa")})

	att := &ExclusionAttestation{
		HasExclusions: true,
		MerkleRoot:    tree.Root,
	}
	if err := SignAttestation(att, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestation(att, pub); err != nil {
		t.Fatalf("valid attestation failed verification: %v", err)
	}
}

func TestExclusionAttestation_RejectTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	att := &ExclusionAttestation{
		HasExclusions: true,
		MerkleRoot:    blake3.Sum256([]byte("original")),
	}
	if err := SignAttestation(att, priv); err != nil {
		t.Fatal(err)
	}

	// Tamper with the root.
	att.MerkleRoot = blake3.Sum256([]byte("tampered"))
	if err := VerifyAttestation(att, pub); err == nil {
		t.Fatal("tampered attestation should fail verification")
	}
}

func TestExclusionAttestation_RejectWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	att := &ExclusionAttestation{
		HasExclusions: false,
		MerkleRoot:    EmptyRoot,
	}
	if err := SignAttestation(att, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestation(att, otherPub); err == nil {
		t.Fatal("attestation should fail with wrong public key")
	}
}

func TestBuildFromDir(t *testing.T) {
	dir := t.TempDir()

	// Create files.
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "util.go", "package util")
	writeFile(t, dir, "secret.env", "PASSWORD=hunter2")

	tree, err := BuildFromDir(dir, []string{"*.env"})
	if err != nil {
		t.Fatal(err)
	}

	if len(tree.Leaves) != 2 {
		t.Fatalf("expected 2 leaves (*.env excluded), got %d", len(tree.Leaves))
	}

	// Verify excluded file is not in tree.
	for _, l := range tree.Leaves {
		if l.Path == "secret.env" {
			t.Fatal("secret.env should be excluded")
		}
	}
}

func TestBuildFromDir_AllExcluded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.env", "secret1")
	writeFile(t, dir, "b.env", "secret2")

	tree, err := BuildFromDir(dir, []string{"*.env"})
	if err != nil {
		t.Fatal(err)
	}
	if tree.Root != EmptyRoot {
		t.Fatal("all-excluded tree should have empty root")
	}
}

func TestBuildFromDir_AttpIgnore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "credentials.json", `{"key":"secret"}`)
	writeFile(t, dir, ".attpignore", "credentials.json\n")

	tree, err := BuildFromDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree.Leaves) != 1 {
		t.Fatalf("expected 1 leaf (.attpignore should exclude credentials.json), got %d", len(tree.Leaves))
	}
	if tree.Leaves[0].Path != "main.go" {
		t.Fatalf("expected main.go, got %s", tree.Leaves[0].Path)
	}
}

func TestBuildFromDirCached(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package a")
	writeFile(t, dir, "b.go", "package b")

	cache := NewFileCache()

	// First build populates cache.
	tree1, err := BuildFromDirCached(dir, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	if cache.Hits() != 2 {
		t.Fatalf("cache should have 2 entries, got %d", cache.Hits())
	}

	// Second build should use cache (same mtime/size).
	tree2, err := BuildFromDirCached(dir, nil, cache)
	if err != nil {
		t.Fatal(err)
	}

	if tree1.Root != tree2.Root {
		t.Fatal("cached rebuild should produce same root")
	}

	// Modify a file — cache should miss for that file.
	// Sleep briefly to ensure mtime changes.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, dir, "a.go", "package a // modified")

	tree3, err := BuildFromDirCached(dir, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	if tree3.Root == tree1.Root {
		t.Fatal("modified file should produce different root")
	}
}

func TestInclusionProof_SingleEntry(t *testing.T) {
	entries := []Entry{makeEntry("only.txt", "only")}
	tree := BuildFromEntries(entries)

	proof, err := InclusionProof(tree, "only.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(tree.Root, "only.txt", entries[0].ContentHash, proof) {
		t.Fatal("single-entry inclusion proof should verify")
	}
}

func TestCanonicalPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"src/Main.Go", "src/main.go"},
		{"SRC\\MAIN.GO", "src/main.go"},
		{"README.md", "readme.md"},
	}
	for _, tt := range tests {
		got := canonicalPath(tt.input)
		if got != tt.want {
			t.Errorf("canonicalPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
