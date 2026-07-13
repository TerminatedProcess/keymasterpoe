package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
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

func TestListKeysAndMembership(t *testing.T) {
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
	if !m.names[panelVault]["shared"] || !m.names[panelPublic]["shared"] {
		t.Fatal("shared should be in both VAULT and PUBLIC")
	}
	if m.names[panelVault]["public-only"] {
		t.Fatal("public-only should not be in VAULT")
	}
	if !m.names[panelPublic]["public-only"] {
		t.Fatal("public-only should be in PUBLIC")
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

	m.groupsPath = filepath.Join(t.TempDir(), "groups.json")
	m.assignGroup("alpha-key", "letters") // render a group header + info box
	m.reload()

	mm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = mm.(model)

	if out := m.View(); len(out) == 0 {
		t.Fatal("empty view")
	}
	// exercise each mode's prompt + the help screen
	for _, mode := range []mode{modeNormal, modeFilter, modeAddName, modeAddDesc, modeConfirm, modeWipeConfirm, modeGroupAssign} {
		m.mode = mode
		m.pending = pending{kind: "copy", key: "alpha-key", src: panelVault, dst: panelPublic}
		m.wipeTgt = panelPublic
		m.groupKey = "beta-key"
		if out := m.View(); len(out) == 0 {
			t.Fatalf("empty view in mode %d", mode)
		}
	}
	// drilled-into-group view must render too
	m.mode = modeNormal
	m.openGroup[panelVault] = "letters"
	if out := m.View(); len(out) == 0 {
		t.Fatal("empty view in opened group")
	}
	m.openGroup[panelVault] = ""
	m.mode = modeNormal
	m.showHelp = true
	if out := m.View(); len(out) == 0 {
		t.Fatal("empty help screen")
	}
}

// TestIndicators verifies the unified indicator language across all three panes.
// Not-in-VAULT and reach both render as ●, distinguished only by color, so we
// force an ANSI256 profile and assert on the color codes.
func TestIndicators(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	const red, green, purple = "38;5;196", "38;5;82", "38;5;141"

	m := newTestModel(t)
	// key2 lives in all three stores; orphan only in public (not backed up).
	setKey(t, m, m.vaultDir, "key2", "", "v")
	setKey(t, m, m.publicDir, "key2", "", "v")
	setKey(t, m, m.projectDir, "key2", "", "v")
	setKey(t, m, m.publicDir, "orphan", "", "v")
	m.reload()

	if k := m.selected(); k == nil { // selection sanity (active defaults to vault)
		t.Fatal("selected() = nil")
	}

	// VAULT: deployed to PUBLIC+PROJECT → green + purple dots, never red.
	v := m.renderRow(Key{Name: "key2"}, panelVault, false, 40)
	if !contains(v, green) || !contains(v, purple) || contains(v, red) {
		t.Fatalf("vault key2 should be green+purple, no red: %q", v)
	}
	// PUBLIC key2: backed up (no red) AND also in PROJECT (purple dot).
	pu := m.renderRow(Key{Name: "key2"}, panelPublic, false, 40)
	if contains(pu, red) || !contains(pu, purple) {
		t.Fatalf("public key2 should be purple, no red: %q", pu)
	}
	// PROJECT key2: backed up (no red) AND also in PUBLIC (green dot).
	pr := m.renderRow(Key{Name: "key2"}, panelProject, false, 40)
	if contains(pr, red) || !contains(pr, green) {
		t.Fatalf("project key2 should be green, no red: %q", pr)
	}
	// orphan in PUBLIC but not VAULT → red dot (not backed up).
	o := m.renderRow(Key{Name: "orphan"}, panelPublic, false, 40)
	if !contains(o, red) {
		t.Fatalf("orphan public should show red not-in-vault dot: %q", o)
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

// TestValueDriftDetection checks the external-hash comparison flags only real
// value differences (never the plaintext into keymaster).
func TestValueDriftDetection(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.vaultDir, "same", "", "identical")
	setKey(t, m, m.publicDir, "same", "", "identical")
	setKey(t, m, m.vaultDir, "diff", "", "value-A")
	setKey(t, m, m.publicDir, "diff", "", "value-B")
	m.reload()

	m.checkDrift("same")
	if len(m.driftBad) != 0 {
		t.Fatalf("identical values flagged as drift: %v / %q", m.driftBad, m.driftText)
	}
	m.checkDrift("diff")
	if !m.driftBad[panelPublic] {
		t.Fatalf("differing values not flagged: %v / %q", m.driftBad, m.driftText)
	}
}

// TestSyncBackfillAndConflict exercises panel→VAULT sync: backfill of missing
// keys, conflict detection on differing values, and override resolution.
func TestSyncBackfillAndConflict(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.publicDir, "new-key", "d1", "v-new")     // not in vault
	setKey(t, m, m.publicDir, "match-key", "", "same")      // == vault
	setKey(t, m, m.vaultDir, "match-key", "", "same")
	setKey(t, m, m.publicDir, "diff-key", "", "public-val") // != vault
	setKey(t, m, m.vaultDir, "diff-key", "", "vault-val")
	m.reload()
	m.active = panelPublic

	m.startSync()

	if !m.names[panelVault]["new-key"] {
		t.Fatal("new-key was not backfilled into VAULT")
	}
	if len(m.syncConflicts) != 1 || m.syncConflicts[0] != "diff-key" {
		t.Fatalf("expected diff-key as the sole conflict, got %v", m.syncConflicts)
	}
	if m.mode != modeSyncConflict {
		t.Fatalf("expected modeSyncConflict, got %d", m.mode)
	}

	// override the conflict → VAULT value should now match PUBLIC's
	mm, _ := m.handleSyncConflictKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = mm.(model)
	if renderHash(t, m, m.vaultDir, "diff-key") != renderHash(t, m, m.publicDir, "diff-key") {
		t.Fatal("override did not replace the VAULT value")
	}
}

// TestGroupAssignSaveLoad checks a key can be assigned to a group, the registry
// persists, and reload reads it back — with one-group-per-key enforced.
func TestGroupAssignSaveLoad(t *testing.T) {
	m := newTestModel(t)
	m.groupsPath = filepath.Join(t.TempDir(), "groups.json")
	setKey(t, m, m.vaultDir, "docuseal-api-key", "", "v")
	m.reload()

	m.assignGroup("docuseal-api-key", "docuseal")
	if err := m.saveGroups(); err != nil {
		t.Fatal(err)
	}
	if got := m.groupOf("docuseal-api-key"); got != "docuseal" {
		t.Fatalf("groupOf = %q, want docuseal", got)
	}
	// reassign to another group must move it, not duplicate
	m.assignGroup("docuseal-api-key", "billing")
	if got := m.groupOf("docuseal-api-key"); got != "billing" {
		t.Fatalf("after reassign groupOf = %q, want billing", got)
	}
	if _, ok := m.groups["docuseal"]; ok {
		t.Fatal("emptied group docuseal should be deleted")
	}

	// persist + fresh load
	m.assignGroup("docuseal-api-key", "docuseal")
	if err := m.saveGroups(); err != nil {
		t.Fatal(err)
	}
	loaded := loadGroups(m.groupsPath)
	if len(loaded["docuseal"]) != 1 || loaded["docuseal"][0] != "docuseal-api-key" {
		t.Fatalf("loaded registry wrong: %v", loaded)
	}
}

// TestGroupPropagation checks that adding a key to a group copies it into VAULT
// and into any deployment store that already holds the group.
func TestGroupPropagation(t *testing.T) {
	m := newTestModel(t)
	m.groupsPath = filepath.Join(t.TempDir(), "groups.json")
	// group already present in PROJECT (one member), plus a loose key in PUBLIC.
	setKey(t, m, m.projectDir, "docuseal-api-key", "", "v1")
	setKey(t, m, m.vaultDir, "docuseal-api-key", "", "v1")
	setKey(t, m, m.publicDir, "docuseal-token", "", "v2") // only in PUBLIC
	m.reload()
	m.assignGroup("docuseal-api-key", "docuseal")
	m.reload()

	// now add docuseal-token to the group → should land in VAULT (master) and in
	// PROJECT (where the group is deployed), but NOT be forced anywhere else.
	m.assignGroup("docuseal-token", "docuseal")
	n, err := m.propagateGroupKey("docuseal-token", "docuseal")
	if err != nil {
		t.Fatalf("propagate: %v", err)
	}
	m.reload()
	if !m.names[panelVault]["docuseal-token"] {
		t.Fatal("token not mirrored into VAULT")
	}
	if !m.names[panelProject]["docuseal-token"] {
		t.Fatal("token not enforced into PROJECT (group already deployed there)")
	}
	if n < 2 {
		t.Fatalf("expected ≥2 propagation copies, got %d", n)
	}
}

// TestGroupRowsAndPush checks the collapsed row model and pushing a whole group.
func TestGroupRowsAndPush(t *testing.T) {
	m := newTestModel(t)
	m.groupsPath = filepath.Join(t.TempDir(), "groups.json")
	setKey(t, m, m.vaultDir, "docuseal-api-key", "", "v")
	setKey(t, m, m.vaultDir, "docuseal-token", "", "v")
	setKey(t, m, m.vaultDir, "loose-key", "", "v")
	m.reload()
	m.assignGroup("docuseal-api-key", "docuseal")
	m.assignGroup("docuseal-token", "docuseal")
	m.reload()

	// collapsed VAULT: one group header + one ungrouped key = 2 rows
	rows := m.rows(panelVault)
	if len(rows) != 2 || rows[0].group != "docuseal" || rows[1].key == nil {
		t.Fatalf("collapsed rows wrong: %+v", rows)
	}
	// drill in → two member keys
	m.openGroup[panelVault] = "docuseal"
	if got := m.rows(panelVault); len(got) != 2 || got[0].key == nil {
		t.Fatalf("opened group rows wrong: %+v", got)
	}
	m.openGroup[panelVault] = ""

	// push the whole group VAULT → PUBLIC
	m.active = panelVault
	m.cursors[panelVault] = 0 // group header
	m.doPushGroup("docuseal", panelVault, panelPublic)
	if !m.names[panelPublic]["docuseal-api-key"] || !m.names[panelPublic]["docuseal-token"] {
		t.Fatal("group push did not copy all members to PUBLIC")
	}
	if m.names[panelPublic]["loose-key"] {
		t.Fatal("push should not have copied the ungrouped key")
	}
}

// TestVaultDeleteScope checks the VAULT delete rules build the right rm queue.
func TestVaultDeleteScope(t *testing.T) {
	m := newTestModel(t)
	setKey(t, m, m.vaultDir, "k", "", "v")
	setKey(t, m, m.projectDir, "k", "", "v") // deployed to PROJECT only
	m.reload()
	m.active = panelVault
	m.cursors[panelVault] = 0
	m.startDelete() // deployed → should enter scope modal, not delete yet
	if m.mode != modeVDelete {
		t.Fatalf("expected modeVDelete for a deployed vault key, got %d", m.mode)
	}
	// choose "vault only" → queue is just VAULT
	m.rmKey = "k"
	mm, _ := m.handleVDeleteKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	m = mm.(model)
	// after runRmQueue pops VAULT, queue is drained (rm itself runs via ExecProcess)
	if len(m.rmQueue) != 0 {
		t.Fatalf("expected queue drained to 0 after popping VAULT, got %v", m.rmQueue)
	}
}
