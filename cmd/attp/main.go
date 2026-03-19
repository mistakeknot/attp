package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mistakeknot/attp/pkg/merkle"
	"github.com/mistakeknot/attp/pkg/safety"
	"github.com/mistakeknot/attp/pkg/server"
	"github.com/mistakeknot/attp/pkg/token"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "pack":
		err = cmdPack()
	case "unpack":
		err = cmdUnpack()
	case "verify":
		err = cmdVerify()
	case "serve":
		err = cmdServe()
	case "version":
		fmt.Printf("attp %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `attp — Agent Token Transfer Protocol

Usage: attp <command> [args]

Commands:
  init             Initialize attp (keypair, config, .attpignore)
  pack             Build a token from current repo state
  unpack <file>    Parse and display a token
  verify <file>    Verify a token's integrity
  serve            Start MCP server (stdio)
  version          Print version
`)
}

// configDir returns ~/.config/attp, creating it if needed.
func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "attp")
	return dir, nil
}

func cmdInit() error {
	cfgDir, err := configDir()
	if err != nil {
		return err
	}
	keysDir := filepath.Join(cfgDir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}

	// Generate ed25519 keypair if not already present.
	privPath := filepath.Join(keysDir, "id_ed25519")
	pubPath := filepath.Join(keysDir, "id_ed25519.pub")
	keysCreated := false
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generating keypair: %w", err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: priv.Seed(),
		})
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			return fmt.Errorf("writing private key: %w", err)
		}
		pubHex := hex.EncodeToString(pub)
		if err := os.WriteFile(pubPath, []byte(pubHex+"\n"), 0644); err != nil {
			return fmt.Errorf("writing public key: %w", err)
		}
		keysCreated = true
	}

	// Create config.yaml if not present.
	configPath := filepath.Join(cfgDir, "config.yaml")
	configCreated := false
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		cfg := fmt.Sprintf("peer_id: %s\nport: 8400\nkey_path: %s\n", hostname, keysDir)
		if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}
		configCreated = true
	}

	// Create .attpignore in current directory if not present.
	ignoreCreated := false
	if _, err := os.Stat(".attpignore"); os.IsNotExist(err) {
		content := strings.Join([]string{
			"# attp exclusion patterns",
			".env",
			"*.key",
			"*.pem",
			"credentials*",
			"secrets*",
			".git",
			"attp-token.json",
			"",
		}, "\n")
		if err := os.WriteFile(".attpignore", []byte(content), 0644); err != nil {
			return fmt.Errorf("writing .attpignore: %w", err)
		}
		ignoreCreated = true
	}

	fmt.Println("attp initialized:")
	if keysCreated {
		fmt.Printf("  keypair: %s\n", keysDir)
	} else {
		fmt.Printf("  keypair: %s (already exists)\n", keysDir)
	}
	if configCreated {
		fmt.Printf("  config:  %s\n", configPath)
	} else {
		fmt.Printf("  config:  %s (already exists)\n", configPath)
	}
	if ignoreCreated {
		fmt.Println("  ignore:  .attpignore")
	} else {
		fmt.Println("  ignore:  .attpignore (already exists)")
	}
	return nil
}

func cmdPack() error {
	// Detect git repo.
	branch, err := gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("not a git repository or git not available: %w", err)
	}
	commit, err := gitOutput("rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("cannot get commit hash: %w", err)
	}
	repoURL, _ := gitOutput("config", "--get", "remote.origin.url")
	if repoURL == "" {
		// Use directory name as fallback.
		wd, _ := os.Getwd()
		repoURL = filepath.Base(wd)
	}

	// Detect dirty files.
	dirtyOutput, _ := gitOutput("status", "--porcelain")
	var dirtyPaths []string
	if dirtyOutput != "" {
		for _, line := range strings.Split(dirtyOutput, "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 3 {
				dirtyPaths = append(dirtyPaths, strings.TrimSpace(line[2:]))
			}
		}
	}

	// Load exclusion patterns from .attpignore.
	var excludePatterns []string
	if data, err := os.ReadFile(".attpignore"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				excludePatterns = append(excludePatterns, line)
			}
		}
	}

	// Build Merkle tree.
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working directory: %w", err)
	}
	tree, err := merkle.BuildFromDir(wd, excludePatterns)
	if err != nil {
		return fmt.Errorf("building merkle tree: %w", err)
	}
	merkleRoot := hex.EncodeToString(tree.Root[:])

	// Load keypair for signing.
	privKey, err := loadPrivateKey()
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	// Sign exclusion attestation.
	hasExclusions := len(excludePatterns) > 0
	att := &merkle.ExclusionAttestation{
		HasExclusions: hasExclusions,
		MerkleRoot:    tree.Root,
	}
	if err := merkle.SignAttestation(att, privKey); err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	// Convert merkle attestation to token attestation.
	tokenAtt := &token.ExclusionAttestation{
		MerkleRoot: hex.EncodeToString(att.MerkleRoot[:]),
		Timestamp:  att.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Nonce:      hex.EncodeToString(att.Nonce[:]),
		Signature:  hex.EncodeToString(att.Signature),
	}

	hostname, _ := os.Hostname()

	// Build token.
	b := token.NewBuilder()
	b.SetRepo(repoURL, branch, commit, dirtyPaths, merkleRoot)
	b.SetSensitivity(hasExclusions, excludePatterns, tokenAtt)
	b.SetProvenance(
		token.Origin{
			AgentID:      "attp-cli",
			AgentVersion: version,
			Machine:      &token.Machine{Hostname: hostname},
		},
		map[string]token.Participant{
			"attp-cli": {Role: "sender", VectorClockIndex: 1},
		},
		map[string]int{"attp-cli": 1},
		1,
	)

	// Add dirty files as payloads.
	inlinedCount := 0
	refCount := 0
	for _, dp := range dirtyPaths {
		content, err := os.ReadFile(dp)
		if err != nil {
			continue // skip files that can't be read (deleted, etc.)
		}
		b.AddPayload(dp, content)
		if len(content) < token.InlineThreshold {
			inlinedCount++
		} else {
			refCount++
		}
	}

	tok, err := b.Build()
	if err != nil {
		return fmt.Errorf("building token: %w", err)
	}

	// Write token to file.
	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}
	if err := os.WriteFile("attp-token.json", data, 0644); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	fmt.Printf("Token packed: attp-token.json\n")
	fmt.Printf("  repo:     %s @ %s (%s)\n", repoURL, branch, commit[:8])
	fmt.Printf("  files:    %d in tree, %d excluded\n", len(tree.Leaves), len(excludePatterns))
	fmt.Printf("  payloads: %d inlined, %d referenced\n", inlinedCount, refCount)
	fmt.Printf("  merkle:   %s\n", merkleRoot[:16]+"...")
	return nil
}

func cmdUnpack() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: attp unpack <file>")
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	tok, err := token.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing token: %w", err)
	}

	qt := safety.Quarantine(tok)
	fmt.Print(safety.FormatQuarantined(qt))

	// Show repo state.
	fmt.Printf("\nRepo: %s\n", tok.Repo.URL)
	fmt.Printf("  branch: %s\n", tok.Repo.Branch)
	fmt.Printf("  commit: %s\n", tok.Repo.Commit)
	if len(tok.Repo.DirtyPaths) > 0 {
		fmt.Printf("  dirty:  %s\n", strings.Join(tok.Repo.DirtyPaths, ", "))
	}

	// Payloads.
	if len(tok.Payloads) > 0 {
		fmt.Printf("\nPayloads (%d):\n", len(tok.Payloads))
		for _, p := range tok.Payloads {
			fmt.Printf("  [%s] %s (%d bytes)\n", p.Mode, p.Path, p.SizeBytes)
		}
	}

	// Requests.
	if len(tok.Requests) > 0 {
		fmt.Printf("\nRequests (%d):\n", len(tok.Requests))
		for _, r := range tok.Requests {
			fmt.Printf("  [%s] %s\n", r.Kind, r.Summary)
		}
	}

	// Decisions.
	if len(tok.Decisions) > 0 {
		fmt.Printf("\nDecisions (%d):\n", len(tok.Decisions))
		for _, d := range tok.Decisions {
			fmt.Printf("  %s\n", d.Summary)
		}
	}
	return nil
}

func cmdVerify() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: attp verify <file>")
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	tok, err := token.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing token: %w", err)
	}

	allPassed := true

	// Check 1: Token structure (already validated by Parse).
	fmt.Println("PASS  token structure valid")

	// Check 2: Payload hash consistency.
	for i, p := range tok.Payloads {
		if p.Mode == "inline" && p.Hash != "" && p.Content != "" {
			err := safety.VerifyLazyFetch([]byte(p.Content), p.Hash)
			if err != nil {
				fmt.Printf("FAIL  payload[%d] %s: hash mismatch\n", i, p.Path)
				allPassed = false
			} else {
				fmt.Printf("PASS  payload[%d] %s: hash verified\n", i, p.Path)
			}
		} else if p.Mode == "ref" {
			fmt.Printf("SKIP  payload[%d] %s: ref (content not available)\n", i, p.Path)
		}
	}

	// Check 3: Exclusion attestation structure.
	if tok.Sensitivity.ExclusionAttestation != nil {
		att := tok.Sensitivity.ExclusionAttestation
		if att.MerkleRoot == "" {
			fmt.Println("FAIL  exclusion attestation: missing merkle_root")
			allPassed = false
		} else if att.Signature == "" {
			fmt.Println("FAIL  exclusion attestation: missing signature")
			allPassed = false
		} else if att.Nonce == "" {
			fmt.Println("FAIL  exclusion attestation: missing nonce")
			allPassed = false
		} else {
			fmt.Println("PASS  exclusion attestation: structure valid")
			// Signature verification requires sender's public key.
			// For now, just report structure is valid.
			fmt.Println("SKIP  exclusion attestation: signature (no sender public key)")
		}
	} else {
		fmt.Println("SKIP  exclusion attestation: not present")
	}

	if allPassed {
		fmt.Println("\nAll checks passed.")
	} else {
		fmt.Println("\nSome checks failed.")
		return fmt.Errorf("verification failed")
	}
	return nil
}

func cmdServe() error {
	cfgDir, err := configDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(cfgDir, "config.yaml")
	peerID := "attp-server"
	port := "8400"

	// Load simple key:value config.
	if data, err := os.ReadFile(configPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "peer_id":
				peerID = val
			case "port":
				port = val
			}
		}
	}

	cfg := server.Config{
		PeerID:      peerID,
		DisplayName: peerID,
		ListenAddr:  ":" + port,
		Confirmer:   safety.AlwaysConfirm{},
	}
	srv := server.New(cfg)
	fmt.Fprintf(os.Stderr, "attp MCP server starting (peer_id=%s, stdio mode)\n", peerID)
	return srv.Run(context.Background())
}

// gitOutput runs a git command and returns trimmed stdout.
func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// loadPrivateKey loads the ed25519 private key from ~/.config/attp/keys/.
func loadPrivateKey() (ed25519.PrivateKey, error) {
	cfgDir, err := configDir()
	if err != nil {
		return nil, err
	}
	privPath := filepath.Join(cfgDir, "keys", "id_ed25519")
	data, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key (run 'attp init' first): %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in %s", privPath)
	}
	seed := block.Bytes
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key size in %s: expected %d bytes, got %d", privPath, ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
