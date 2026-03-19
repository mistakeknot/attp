// Package merkle implements a flat sorted binary Merkle tree with BLAKE3
// and exclusion attestations for attp's sensitivity boundary.
//
// Tree construction:
//   - Leaves are sorted by canonical path (forward-slash, lowercase).
//   - Leaf hash: BLAKE3(key=BLAKE3(canonical_path), data=file_content) — keyed mode, domain-separated.
//   - Interior nodes: BLAKE3(left || right).
//   - Empty tree root: BLAKE3("attp-empty-tree").
package merkle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"
	"github.com/zeebo/blake3"
)

// EmptyRoot is the domain-separated Merkle root for an empty tree.
var EmptyRoot = blake3.Sum256([]byte("attp-empty-tree"))

// Entry is a single file entry in the Merkle tree.
type Entry struct {
	Path        string   // canonical path (forward-slash, lowercase)
	ContentHash [32]byte // BLAKE3 hash of file content
}

// LeafHash computes the keyed leaf hash for an entry:
// BLAKE3(key=BLAKE3(canonical_path), data=file_content_hash).
// Note: for actual tree building from directories, the content hash
// is computed from file content directly. This function produces the
// leaf hash that goes into the tree from a pre-computed content hash.
func (e *Entry) LeafHash() [32]byte {
	pathKey := blake3.Sum256([]byte(e.Path))
	h, _ := blake3.NewKeyed(pathKey[:])
	h.Write(e.ContentHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// leafHashFromContent computes the keyed leaf hash from raw content:
// BLAKE3(key=BLAKE3(canonical_path), data=content).
func leafHashFromContent(canonicalPath string, content []byte) [32]byte {
	pathKey := blake3.Sum256([]byte(canonicalPath))
	h, _ := blake3.NewKeyed(pathKey[:])
	h.Write(content)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ProofNode is a single node in an inclusion proof path.
type ProofNode struct {
	Hash   [32]byte
	IsLeft bool // true if this sibling is the left child
}

// Tree is a flat sorted binary Merkle tree.
type Tree struct {
	Root   [32]byte   // Merkle root
	Leaves []Entry    // sorted leaf entries
	Nodes  [][32]byte // full node array (leaves at end, root at index 0)
}

// BuildFromEntries builds a Merkle tree from pre-computed entries.
// Entries are sorted by canonical path before tree construction.
func BuildFromEntries(entries []Entry) *Tree {
	if len(entries) == 0 {
		return &Tree{Root: EmptyRoot}
	}

	// Sort by canonical path.
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	// Compute leaf hashes.
	leafHashes := make([][32]byte, len(sorted))
	for i := range sorted {
		leafHashes[i] = sorted[i].LeafHash()
	}

	// Build balanced binary tree stored as array.
	// We use a bottom-up approach: pad leaves to next power of 2,
	// then compute interior nodes.
	n := nextPow2(len(leafHashes))
	// Total nodes in a complete binary tree with n leaves = 2*n - 1.
	// Layout: nodes[0] = root, nodes[n-1 .. 2*n-2] = leaves.
	nodes := make([][32]byte, 2*n)
	// Place leaf hashes at positions [n .. n+len-1].
	for i, lh := range leafHashes {
		nodes[n+i] = lh
	}
	// Pad remaining leaves with zero hash (empty sentinel).
	// They are already zero-valued, which is fine.

	// Build interior nodes bottom-up.
	for i := n - 1; i >= 1; i-- {
		left := nodes[2*i]
		right := nodes[2*i+1]
		var combined [64]byte
		copy(combined[:32], left[:])
		copy(combined[32:], right[:])
		nodes[i] = blake3.Sum256(combined[:])
	}

	return &Tree{
		Root:   nodes[1],
		Leaves: sorted,
		Nodes:  nodes,
	}
}

// InclusionProof generates an O(log N) inclusion proof for the given path.
func InclusionProof(tree *Tree, path string) ([]ProofNode, error) {
	canonical := canonicalPath(path)
	idx := -1
	for i, e := range tree.Leaves {
		if e.Path == canonical {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("path %q not found in tree", path)
	}

	if len(tree.Nodes) == 0 {
		return nil, fmt.Errorf("tree has no nodes")
	}

	n := nextPow2(len(tree.Leaves))
	pos := n + idx // position in the node array

	var proof []ProofNode
	for pos > 1 {
		sibling := pos ^ 1 // XOR with 1 gives the sibling
		isLeft := sibling < pos
		proof = append(proof, ProofNode{
			Hash:   tree.Nodes[sibling],
			IsLeft: isLeft,
		})
		pos /= 2
	}
	return proof, nil
}

// VerifyInclusion verifies an inclusion proof for a given path and content hash.
func VerifyInclusion(root [32]byte, path string, contentHash [32]byte, proof []ProofNode) bool {
	entry := Entry{Path: canonicalPath(path), ContentHash: contentHash}
	current := entry.LeafHash()

	for _, node := range proof {
		var combined [64]byte
		if node.IsLeft {
			copy(combined[:32], node.Hash[:])
			copy(combined[32:], current[:])
		} else {
			copy(combined[:32], current[:])
			copy(combined[32:], node.Hash[:])
		}
		current = blake3.Sum256(combined[:])
	}

	return current == root
}

// ExclusionAttestation attests to the exclusion state of a Merkle tree.
type ExclusionAttestation struct {
	HasExclusions bool
	MerkleRoot    [32]byte
	Timestamp     time.Time
	Nonce         [16]byte
	Signature     []byte
}

// attestationMessage builds the message to sign/verify:
// BLAKE3(has_exclusions || merkle_root || timestamp_unix || nonce)
func attestationMessage(a *ExclusionAttestation) [32]byte {
	var buf bytes.Buffer
	if a.HasExclusions {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	buf.Write(a.MerkleRoot[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(a.Timestamp.Unix()))
	buf.Write(ts[:])
	buf.Write(a.Nonce[:])
	return blake3.Sum256(buf.Bytes())
}

// SignAttestation signs an exclusion attestation with an Ed25519 private key.
// It generates a random nonce and sets the timestamp if zero.
func SignAttestation(a *ExclusionAttestation, key ed25519.PrivateKey) error {
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}
	if _, err := rand.Read(a.Nonce[:]); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	msg := attestationMessage(a)
	a.Signature = ed25519.Sign(key, msg[:])
	return nil
}

// VerifyAttestation verifies an exclusion attestation signature.
func VerifyAttestation(a *ExclusionAttestation, key ed25519.PublicKey) error {
	if len(a.Signature) == 0 {
		return errors.New("attestation has no signature")
	}
	msg := attestationMessage(a)
	if !ed25519.Verify(key, msg[:], a.Signature) {
		return errors.New("attestation signature verification failed")
	}
	return nil
}

// FileCache caches file content hashes by path, keyed on mtime+size.
type FileCache struct {
	mu      sync.RWMutex
	entries map[string]fileCacheEntry
}

type fileCacheEntry struct {
	Mtime time.Time
	Size  int64
	Hash  [32]byte
}

// NewFileCache creates a new empty file cache.
func NewFileCache() *FileCache {
	return &FileCache{entries: make(map[string]fileCacheEntry)}
}

// Lookup returns the cached hash for a path if mtime and size match.
func (c *FileCache) Lookup(path string, info fs.FileInfo) ([32]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[path]
	if !ok {
		return [32]byte{}, false
	}
	if e.Mtime.Equal(info.ModTime()) && e.Size == info.Size() {
		return e.Hash, true
	}
	return [32]byte{}, false
}

// Store records a hash for a path with its current mtime and size.
func (c *FileCache) Store(path string, info fs.FileInfo, hash [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[path] = fileCacheEntry{
		Mtime: info.ModTime(),
		Size:  info.Size(),
		Hash:  hash,
	}
}

// Hits returns the number of cache entries (for testing).
func (c *FileCache) Hits() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// BuildFromDir walks a directory, applies exclusion patterns, and builds a tree.
func BuildFromDir(root string, excludePatterns []string) (*Tree, error) {
	return BuildFromDirCached(root, excludePatterns, nil)
}

// BuildFromDirCached walks a directory with an optional file cache.
func BuildFromDirCached(root string, excludePatterns []string, cache *FileCache) (*Tree, error) {
	matchers, err := compilePatterns(excludePatterns)
	if err != nil {
		return nil, fmt.Errorf("compiling patterns: %w", err)
	}

	// Also load .attpignore if present.
	ignorePatterns, err := loadAttpIgnore(root)
	if err != nil {
		return nil, fmt.Errorf("loading .attpignore: %w", err)
	}
	ignoreMatchers, err := compilePatterns(ignorePatterns)
	if err != nil {
		return nil, fmt.Errorf("compiling .attpignore patterns: %w", err)
	}
	matchers = append(matchers, ignoreMatchers...)

	var entries []Entry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden directories (except root).
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		// Skip .attpignore (attp metadata, not project content).
		if d.Name() == ".attpignore" {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		canonical := canonicalPath(rel)

		if isExcluded(canonical, d.Name(), matchers) {
			return nil
		}

		var contentHash [32]byte
		info, err := d.Info()
		if err != nil {
			return err
		}

		if cache != nil {
			if h, ok := cache.Lookup(path, info); ok {
				contentHash = h
				goto haveHash
			}
		}

		{
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			contentHash = blake3.Sum256(data)
			if cache != nil {
				cache.Store(path, info, contentHash)
			}
		}

	haveHash:
		entries = append(entries, Entry{
			Path:        canonical,
			ContentHash: contentHash,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return BuildFromEntries(entries), nil
}

// canonicalPath normalizes a path: forward slashes, lowercase.
func canonicalPath(p string) string {
	// Replace backslashes explicitly (filepath.ToSlash is a no-op on Linux).
	s := strings.ReplaceAll(p, "\\", "/")
	return strings.ToLower(s)
}

// nextPow2 returns the smallest power of 2 >= n.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// compilePatterns compiles gitignore-style glob patterns.
func compilePatterns(patterns []string) ([]glob.Glob, error) {
	var matchers []glob.Glob
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		matchers = append(matchers, g)
	}
	return matchers, nil
}

// isExcluded checks if a path matches any exclusion pattern.
func isExcluded(canonical string, basename string, matchers []glob.Glob) bool {
	for _, m := range matchers {
		if m.Match(canonical) || m.Match(basename) {
			return true
		}
	}
	return false
}

// loadAttpIgnore reads .attpignore from the given directory root.
func loadAttpIgnore(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, ".attpignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, nil
}
