package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// newTestModel builds a model whose three stores live under a temp root, so
// tests never touch a real vault.
func newTestModel(t *testing.T) model {
	t.Helper()
	avBin, err := resolveAvBin()
	if err != nil {
		t.Skipf("agent-vault not available: %v", err)
	}
	root := t.TempDir()
	return model{
		vaultDir:   filepath.Join(root, "vault"),
		publicDir:  filepath.Join(root, "public"),
		projectDir: filepath.Join(root, "project"),
		avBin:      avBin,
	}
}

// setKey writes a value into a store non-interactively (test helper only — the
// real TUI never does this; values are entered on a TTY).
func setKey(t *testing.T, m model, dir, key, desc, value string) {
	t.Helper()
	args := []string{"set", key, "--stdin"}
	if desc != "" {
		args = append(args, "--desc", desc)
	}
	c := m.av(dir, args...)
	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	stdin.Write([]byte(value))
	stdin.Close()
	if err := c.Wait(); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

// renderHash returns the sha256 of a key's real value WITHOUT the test ever
// holding the plaintext — mirrors how keymaster avoids seeing values.
func renderHash(t *testing.T, m model, dir, key string) [32]byte {
	t.Helper()
	tmp, err := os.CreateTemp("", "kmtest-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := m.av(dir, "write", tmp.Name(), "--content", "<agent-vault:"+key+">").Run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func TestCopyKeyRoundTrip(t *testing.T) {
	m := newTestModel(t)
	const val = "sk-abc123!@#$%^&*()_+-=/\\ no-newline"
	setKey(t, m, m.publicDir, "api-key", "the api key", val)

	if err := m.copyKeyOp("api-key", "the api key", m.publicDir, m.vaultDir); err != nil {
		t.Fatalf("copyKeyOp: %v", err)
	}

	// value must be byte-identical after the relay
	if renderHash(t, m, m.publicDir, "api-key") != renderHash(t, m, m.vaultDir, "api-key") {
		t.Fatal("value differs after copy — round-trip not lossless")
	}

	// description must carry across
	m.reload()
	var got Key
	for _, k := range m.keys[panelVault] {
		if k.Name == "api-key" {
			got = k
		}
	}
	if got.Name == "" {
		t.Fatal("copied key not found in VAULT")
	}
	if got.Desc != "the api key" {
		t.Fatalf("desc not preserved: got %q", got.Desc)
	}
}

func TestOverwriteSemantics(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.publicDir, "k", "", "value-one")
	setKey(t, m, m.vaultDir, "k", "", "value-two")

	// copy public→vault should overwrite vault's copy with public's value
	if err := m.copyKeyOp("k", "", m.publicDir, m.vaultDir); err != nil {
		t.Fatalf("copyKeyOp: %v", err)
	}
	if renderHash(t, m, m.publicDir, "k") != renderHash(t, m, m.vaultDir, "k") {
		t.Fatal("overwrite did not replace vault value")
	}
}

func TestListKeysAndDup(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.vaultDir, "shared", "", "v")
	setKey(t, m, m.publicDir, "shared", "", "v")
	setKey(t, m, m.publicDir, "public-only", "", "v")
	m.reload()

	if !m.exists[panelVault] || !m.exists[panelPublic] {
		t.Fatal("stores should exist after set")
	}
	if m.exists[panelProject] {
		t.Fatal("project store should not exist")
	}
	if got := m.dupCount("shared"); got != 2 {
		t.Fatalf("dupCount(shared) = %d, want 2", got)
	}
	if got := m.dupCount("public-only"); got != 1 {
		t.Fatalf("dupCount(public-only) = %d, want 1", got)
	}
}

// TestNoTempLeak ensures copyKeyOp leaves no km-* temp file behind.
func TestNoTempLeak(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.publicDir, "k", "", "secret")

	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "km-*"))
	if err := m.copyKeyOp("k", "", m.publicDir, m.vaultDir); err != nil {
		t.Fatal(err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "km-*"))
	if len(after) > len(before) {
		t.Fatalf("temp file leaked: before=%d after=%d", len(before), len(after))
	}
}

// TestViewSmoke drives the model through its modes and renders each, catching
// panics/index bugs in the View paths without a real terminal.
func TestViewSmoke(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.vaultDir, "alpha-key", "first", "v")
	setKey(t, m, m.vaultDir, "beta-key", "second", "v")
	setKey(t, m, m.publicDir, "alpha-key", "first", "v")
	m.reload()

	mm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = mm.(model)

	if out := m.View(); len(out) == 0 {
		t.Fatal("empty view")
	}
	// exercise each mode's prompt + the help screen
	for _, mode := range []mode{modeNormal, modeFilter, modeAddName, modeAddDesc, modeConfirm} {
		m.mode = mode
		m.pending = pending{kind: "delete", key: "alpha-key", src: panelVault}
		if out := m.View(); len(out) == 0 {
			t.Fatalf("empty view in mode %d", mode)
		}
	}
	m.mode = modeNormal
	m.showHelp = true
	if out := m.View(); len(out) == 0 {
		t.Fatal("empty help screen")
	}
}

// TestSelectionAndDupTag verifies selection tracks the filtered list and the
// dup tag appears for cross-store keys.
func TestSelectionAndDupTag(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.vaultDir, "shared", "", "v")
	setKey(t, m, m.publicDir, "shared", "", "v")
	m.reload()
	m.active = panelVault
	m.cursors[panelVault] = 0
	if k := m.selected(); k == nil || k.Name != "shared" {
		t.Fatalf("selected() = %v, want shared", k)
	}
	row := m.renderRow(Key{Name: "shared"}, panelVault, false, 40)
	if !contains(row, "dup") {
		t.Fatalf("expected ⇄dup tag in row, got %q", row)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
