// keymaster — a cwd-aware TUI to manage agent-vault secrets across three stores:
// a private VAULT (master library), the ambient PUBLIC store, and the current
// PROJECT store. Mirrors the sibling `viewskills` TUI in shape.
//
// Security invariant (the whole point): plaintext secret values NEVER pass
// through this process. The Go code only ever handles file paths and key names.
// Values are relayed store→store through agent-vault-rendered 0600 temp files
// (shredded immediately), and there is NO reveal feature. See SPEC.md / CLAUDE.md.
//
// Value comparison (drift check + sync conflicts) is done by fingerprint only:
// a value is rendered to a 0600 temp and hashed by an EXTERNAL `sha256sum`, so
// the plaintext bytes enter that process, never keymaster's — keymaster holds
// only the one-way digest, compares it, and discards it. No value is displayed
// or persisted. This softens "can't compare" while preserving "never reveal".
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// execFinishedMsg is delivered when a TTY subprocess handed to tea.ExecProcess
// (agent-vault set / rm) returns and the TUI resumes.
type execFinishedMsg struct{ err error }

// Key is one secret entry. Only the non-secret name and description are ever
// held; the value never enters this struct.
type Key struct {
	Name string
	Desc string
}

type panel int

const (
	panelVault   panel = 0
	panelPublic  panel = 1
	panelProject panel = 2
)

type mode int

const (
	modeNormal mode = iota
	modeFilter
	modeAddName
	modeAddDesc
	modeConfirm
	modeSyncConflict // resolving per-key value overrides during a panel sync
	modeWipeConfirm  // typing the pane name to confirm wiping a deployment store
	modeGroupAssign  // typing a group name to add/move the selected key into
)

// pending records an operation awaiting a y/n confirmation.
type pending struct {
	kind  string // "copy" | "move" | "pushgroup"
	key   string
	desc  string
	group string // set for "pushgroup"
	src   panel
	dst   panel
}

// rowItem is one line in a pane's list: either a group header (group != "") or a
// key (key != nil). Collapsed panes show group headers + ungrouped keys; drilling
// into a group shows that group's member keys present in the store.
type rowItem struct {
	group string
	key   *Key
}

// afterExec records work to run once a tea.ExecProcess subprocess returns —
// currently only the auto-mirror of a freshly-added key up into the VAULT.
type afterExec struct {
	mirror  bool
	key     string
	desc    string
	srcDir  string
	editKey string // set when the exec was an in-place VAULT value edit (no mirror)
}

type model struct {
	keys    [3][]Key
	exists  [3]bool // whether the store dir actually exists yet
	names   [3]map[string]bool
	active  panel
	cursors [3]int
	width   int
	height  int

	vaultDir   string
	publicDir  string
	projectDir string
	cwd        string
	avBin      string

	mode         mode
	filter       string // active filter text
	filterActive bool   // filter applied (persists after leaving filter input)
	input        string // add field currently being typed
	addKey       string
	addDesc  string
	addTgt   panel
	pending  pending
	after    afterExec
	showHelp bool

	// on-demand drift check for the selected key (external hash compare)
	driftKey  string        // key the drift result is for ("" = none)
	driftBad  map[panel]bool // stores whose value differs from the baseline
	driftText string        // summary line for the detail box

	// on-demand value reveal for the selected key (breaks the never-reveal
	// invariant deliberately — user opt-in). Keyed to a specific key+pane so it
	// hides again the moment you navigate away; cleared on any reload.
	revealKey   string // key the revealed value is for ("" = none)
	revealPanel panel  // store the value was read from
	revealVal   string // plaintext value (only while revealed)

	// panel → VAULT sync conflict resolution
	syncPanel     panel
	syncConflicts []string // keys in both panel and VAULT with differing values
	syncIdx       int

	// pane wipe: user must type the pane's label to confirm
	wipeTgt panel

	// grouping: a global registry mapping group name → member key names. A key
	// belongs to at most one group. openGroup[p] is the group currently drilled
	// into for pane p ("" = collapsed group view). groupKey is the key awaiting a
	// group assignment in modeGroupAssign.
	groups     map[string][]string
	groupsPath string
	openGroup  [3]string
	groupKey   string
	lastGroup  string // last group name entered, to prefill the next assign prompt

	statusMsg string
	statusErr bool
}

var keyNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

func initialModel(avBin string) model {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	m := model{
		vaultDir:   filepath.Join(home, ".config", "keymasterpoe", "agent-vault", "vault"),
		publicDir:  filepath.Join(home, ".agent-vault"),
		projectDir: filepath.Join(cwd, ".agent-vault"),
		groupsPath: filepath.Join(home, ".config", "keymasterpoe", "groups.json"),
		cwd:        cwd,
		avBin:      avBin,
	}
	m.groups = loadGroups(m.groupsPath)
	m.reload()
	m.reconcileProject() // prune invalid project "symlinks" before the UI appears
	return m
}

// --- grouping -------------------------------------------------------------

// loadGroups reads the global group registry (group name → key names). Membership
// is non-secret metadata, safe to hold and persist as plaintext JSON. A missing or
// unreadable file yields an empty registry.
func loadGroups(path string) map[string][]string {
	g := map[string][]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return g
	}
	_ = json.Unmarshal(b, &g)
	if g == nil {
		g = map[string][]string{}
	}
	return g
}

// saveGroups persists the registry, sorted for a stable on-disk file.
func (m model) saveGroups() error {
	if m.groupsPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.groupsPath), 0o755); err != nil {
		return err
	}
	for g := range m.groups {
		sort.Strings(m.groups[g])
	}
	b, err := json.MarshalIndent(m.groups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.groupsPath, b, 0o644)
}

// groupOf returns the group a key belongs to, or "" if ungrouped.
func (m model) groupOf(key string) string {
	for g, members := range m.groups {
		for _, k := range members {
			if k == key {
				return g
			}
		}
	}
	return ""
}

// groupCount reports how many of a group's members actually exist in store p.
func (m model) groupCount(p panel, group string) int {
	n := 0
	for _, k := range m.keys[p] {
		if m.groupOf(k.Name) == group {
			n++
		}
	}
	return n
}

// descOf returns a key's description from whichever store holds it.
func (m model) descOf(key string) string {
	for p := 0; p < 3; p++ {
		for _, k := range m.keys[p] {
			if k.Name == key {
				return k.Desc
			}
		}
	}
	return ""
}

// assignGroup moves key into group (a key is in at most one group), creating the
// group if needed and dropping the key from any previous group.
func (m *model) assignGroup(key, group string) {
	m.removeFromGroup(key)
	m.groups[group] = append(m.groups[group], key)
}

// removeFromGroup drops key from whatever group holds it, deleting the group if it
// becomes empty.
func (m *model) removeFromGroup(key string) {
	for g, members := range m.groups {
		for i, k := range members {
			if k == key {
				m.groups[g] = append(members[:i], members[i+1:]...)
				if len(m.groups[g]) == 0 {
					delete(m.groups, g)
				}
				return
			}
		}
	}
}

// pruneGroups drops members that no longer exist in any store and deletes emptied
// groups. Keeps the registry from accumulating stale names after deletes/moves.
func (m *model) pruneGroups() {
	anyStore := func(key string) bool {
		return m.names[0][key] || m.names[1][key] || m.names[2][key]
	}
	for g, members := range m.groups {
		kept := members[:0]
		for _, k := range members {
			if anyStore(k) {
				kept = append(kept, k)
			}
		}
		if len(kept) == 0 {
			delete(m.groups, g)
		} else {
			m.groups[g] = kept
		}
	}
}

// propagateGroupKey enforces a group's membership across the stores it already
// lives in: the newly-added key is copied into VAULT (master completeness) and
// into any deployment store (PUBLIC/PROJECT) that already holds the group, so a
// deployed group never goes partial. Silent value relay — nothing is revealed.
func (m *model) propagateGroupKey(key, group string) (int, error) {
	var srcDir string
	for _, p := range []panel{panelVault, panelPublic, panelProject} {
		if m.names[p][key] {
			srcDir = m.dirFor(p)
			break
		}
	}
	if srcDir == "" {
		return 0, nil // key not materialized in any store yet
	}
	desc := m.descOf(key)
	var targets []panel
	if !m.names[panelVault][key] {
		targets = append(targets, panelVault)
	}
	for _, p := range []panel{panelPublic, panelProject} {
		if m.groupCount(p, group) > 0 && !m.names[p][key] {
			targets = append(targets, p)
		}
	}
	n := 0
	for _, p := range targets {
		if err := m.copyKeyOp(key, desc, srcDir, m.dirFor(p)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// --- agent-vault plumbing -------------------------------------------------

// av builds an agent-vault command scoped to a specific store. AGENT_VAULT_DIR
// is always set explicitly so we never accidentally read the ambient store.
func (m model) av(dir string, args ...string) *exec.Cmd {
	c := exec.Command(m.avBin, args...)
	c.Env = append(os.Environ(), "AGENT_VAULT_DIR="+dir)
	return c
}

func (m model) dirFor(p panel) string {
	switch p {
	case panelVault:
		return m.vaultDir
	case panelPublic:
		return m.publicDir
	default:
		return m.projectDir
	}
}

func labelFor(p panel) string {
	switch p {
	case panelVault:
		return "VAULT"
	case panelPublic:
		return "PUBLIC"
	default:
		return "PROJECT"
	}
}

// storeExists reports whether a store has been initialized (has a vault.json).
func storeExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "vault.json"))
	return err == nil
}

// listKeys reads key names + descriptions from a store via `list --json`.
// Non-secret metadata only. Returns nil for a missing/empty store.
func (m model) listKeys(dir string) []Key {
	if !storeExists(dir) {
		return nil
	}
	c := m.av(dir, "list", "--json")
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = nil
	if err := c.Run(); err != nil {
		return nil
	}
	var parsed struct {
		Keys []struct {
			Key  string `json:"key"`
			Desc string `json:"desc"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		return nil
	}
	keys := make([]Key, 0, len(parsed.Keys))
	for _, k := range parsed.Keys {
		keys = append(keys, Key{Name: k.Key, Desc: k.Desc})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys
}

// copyKeyOp relays one key's value from src store to dst store WITHOUT the value
// ever entering this process: agent-vault renders it into a 0600 temp file, then
// `set --stdin` reads that file. The temp is shredded immediately and on error.
func (m model) copyKeyOp(key, desc, srcDir, dstDir string) error {
	tmp, err := os.CreateTemp("", "km-*") // 0600 by default
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer shredFile(tmpPath)

	if err := m.av(srcDir, "write", tmpPath, "--content", "<agent-vault:"+key+">").Run(); err != nil {
		return fmt.Errorf("render value: %w", err)
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	args := []string{"set", key, "--stdin"}
	if desc != "" {
		args = append(args, "--desc", desc)
	}
	c := m.av(dstDir, args...)
	c.Stdin = f
	if err := c.Run(); err != nil {
		return fmt.Errorf("write value: %w", err)
	}
	return nil
}

// valueHash returns a sha256 fingerprint of a key's value WITHOUT the plaintext
// ever entering keymaster: the value is rendered to a 0600 temp (agent-vault
// write) and hashed by an external `sha256sum` — only the digest comes back.
// Temp is shredded. Used solely for equality comparison; never displayed.
func (m model) valueHash(dir, key string) (string, error) {
	tmp, err := os.CreateTemp("", "km-*")
	if err != nil {
		return "", err
	}
	p := tmp.Name()
	tmp.Close()
	defer shredFile(p)
	if err := m.av(dir, "write", p, "--content", "<agent-vault:"+key+">").Run(); err != nil {
		return "", fmt.Errorf("render: %w", err)
	}
	var out bytes.Buffer
	c := exec.Command("sha256sum", p)
	c.Stdout = &out
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	f := strings.Fields(out.String())
	if len(f) == 0 {
		return "", fmt.Errorf("hash: empty output")
	}
	return f[0], nil
}

// revealValue renders a key's plaintext value into a 0600 temp (the sanctioned
// agent-vault write relay), reads it, and shreds the temp. UNLIKE valueHash, the
// plaintext DOES enter this process — this is the deliberate opt-in relaxation of
// the never-reveal invariant for the `v` view/copy feature. Trailing newline (if
// agent-vault appended one) is trimmed so clipboard/detail get the exact value.
func (m model) revealValue(dir, key string) (string, error) {
	tmp, err := os.CreateTemp("", "km-*")
	if err != nil {
		return "", err
	}
	p := tmp.Name()
	tmp.Close()
	defer shredFile(p)
	if err := m.av(dir, "write", p, "--content", "<agent-vault:"+key+">").Run(); err != nil {
		return "", fmt.Errorf("render: %w", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// copyClipboard pipes a value to the system clipboard. Wayland (wl-copy) first,
// then X11 fallbacks. Value transits the child's stdin only — never a temp file.
func copyClipboard(val string) error {
	type tool struct {
		bin  string
		args []string
	}
	for _, t := range []tool{
		{"wl-copy", nil},
		{"xclip", []string{"-selection", "clipboard"}},
		{"xsel", []string{"--clipboard", "--input"}},
	} {
		if _, err := exec.LookPath(t.bin); err != nil {
			continue
		}
		c := exec.Command(t.bin, t.args...)
		c.Stdin = strings.NewReader(val)
		if err := c.Run(); err != nil {
			return fmt.Errorf("%s: %w", t.bin, err)
		}
		return nil
	}
	return fmt.Errorf("no clipboard tool found (install wl-clipboard, xclip, or xsel)")
}

// doReveal reads the selected key's value from the active pane, stashes it for
// the detail box, and copies it to the clipboard.
func (m *model) doReveal() {
	k := m.selected()
	if k == nil {
		m.statusMsg, m.statusErr = "no key selected", true
		return
	}
	val, err := m.revealValue(m.dirFor(m.active), k.Name)
	if err != nil {
		m.statusMsg, m.statusErr = fmt.Sprintf("reveal failed: %v", err), true
		return
	}
	m.revealKey, m.revealPanel, m.revealVal = k.Name, m.active, val
	if err := copyClipboard(val); err != nil {
		m.statusMsg, m.statusErr = fmt.Sprintf("revealed — clipboard failed: %v", err), true
		return
	}
	m.statusMsg, m.statusErr = fmt.Sprintf("%s value revealed + copied to clipboard", k.Name), false
}

// clearReveal drops any revealed plaintext from memory.
func (m *model) clearReveal() { m.revealKey, m.revealVal = "", "" }

// checkDrift fingerprints the key across every store it's in and records which
// stores differ from the baseline (VAULT if present, else the first store).
func (m *model) checkDrift(key string) {
	var stores []panel
	for _, p := range []panel{panelVault, panelPublic, panelProject} {
		if m.names[p][key] {
			stores = append(stores, p)
		}
	}
	m.driftKey, m.driftBad, m.driftText = key, map[panel]bool{}, ""
	if len(stores) < 2 {
		m.driftText = "only in one store — nothing to compare"
		return
	}
	hashes := map[panel]string{}
	for _, p := range stores {
		h, err := m.valueHash(m.dirFor(p), key)
		if err != nil {
			m.driftText = "drift check failed: " + err.Error()
			return
		}
		hashes[p] = h
	}
	base := stores[0] // VAULT first when present
	var parts []string
	for _, p := range stores[1:] {
		if hashes[p] == hashes[base] {
			parts = append(parts, labelFor(p)+"="+labelFor(base))
		} else {
			m.driftBad[p] = true
			parts = append(parts, labelFor(p)+"≠"+labelFor(base))
		}
	}
	m.driftText = "values: " + strings.Join(parts, " · ")
}

// shredFile removes a temp file, preferring `shred -u` to scrub the bytes.
func shredFile(p string) {
	if _, err := exec.LookPath("shred"); err == nil {
		_ = exec.Command("shred", "-u", p).Run()
	}
	_ = os.Remove(p) // backstop in case shred failed or is absent
}

// --- state ----------------------------------------------------------------

func (m *model) reload() {
	if m.groups == nil {
		m.groups = map[string][]string{}
	}
	m.driftKey, m.driftBad, m.driftText = "", nil, "" // stale after membership changes
	m.clearReveal()                                   // don't keep plaintext across a reload
	dirs := [3]string{m.vaultDir, m.publicDir, m.projectDir}
	for i, d := range dirs {
		m.exists[i] = storeExists(d)
		m.keys[i] = m.listKeys(d)
		set := make(map[string]bool, len(m.keys[i]))
		for _, k := range m.keys[i] {
			set[k.Name] = true
		}
		m.names[i] = set
	}
	m.pruneGroups()
	// leave a drilled-in group only if it still has members in that pane
	for i := 0; i < 3; i++ {
		if g := m.openGroup[i]; g != "" && m.groupCount(panel(i), g) == 0 {
			m.openGroup[i] = ""
		}
	}
	m.clampCursors()
}

func (m *model) clampCursors() {
	for i := 0; i < 3; i++ {
		list := m.rows(panel(i))
		if m.cursors[i] >= len(list) {
			m.cursors[i] = max(0, len(list)-1)
		}
	}
}

// rows builds the display list for a pane. Collapsed: group headers (for groups
// with ≥1 member present here) followed by ungrouped keys. Drilled into a group:
// that group's member keys present in the store. The active filter matches group
// names and key names/descriptions.
func (m model) rows(p panel) []rowItem {
	var out []rowItem
	if open := m.openGroup[p]; open != "" {
		for i := range m.keys[p] {
			if m.groupOf(m.keys[p][i].Name) == open {
				out = append(out, rowItem{key: &m.keys[p][i]})
			}
		}
	} else {
		present := map[string]bool{}
		for _, k := range m.keys[p] {
			if g := m.groupOf(k.Name); g != "" {
				present[g] = true
			}
		}
		gs := make([]string, 0, len(present))
		for g := range present {
			gs = append(gs, g)
		}
		sort.Strings(gs)
		for _, g := range gs {
			out = append(out, rowItem{group: g})
		}
		for i := range m.keys[p] {
			if m.groupOf(m.keys[p][i].Name) == "" {
				out = append(out, rowItem{key: &m.keys[p][i]})
			}
		}
	}
	if needle := strings.ToLower(m.filterText()); needle != "" {
		filtered := out[:0:0]
		for _, r := range out {
			if r.group != "" {
				if strings.Contains(strings.ToLower(r.group), needle) {
					filtered = append(filtered, r)
				}
			} else if strings.Contains(strings.ToLower(r.key.Name), needle) ||
				strings.Contains(strings.ToLower(r.key.Desc), needle) {
				filtered = append(filtered, r)
			}
		}
		out = filtered
	}
	return out
}

// filterText is the active filter string (only meaningful in/after filter mode).
func (m model) filterText() string {
	if m.mode == modeFilter || m.filterActive {
		return m.filter
	}
	return ""
}

// currentRow returns the row under the cursor in the active pane.
func (m model) currentRow() (rowItem, bool) {
	list := m.rows(m.active)
	if len(list) == 0 {
		return rowItem{}, false
	}
	idx := m.cursors[m.active]
	if idx >= len(list) {
		idx = len(list) - 1
	}
	return list[idx], true
}

// selected returns the key under the cursor, or nil when the row is a group
// header (or the pane is empty). Key-level ops guard on this.
func (m model) selected() *Key {
	r, ok := m.currentRow()
	if !ok {
		return nil
	}
	return r.key
}

// --- bubbletea ------------------------------------------------------------

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case execFinishedMsg:
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("agent-vault: %v", msg.err)
			m.statusErr = true
		}
		if m.after.mirror {
			if err := m.copyKeyOp(m.after.key, m.after.desc, m.after.srcDir, m.vaultDir); err != nil {
				m.statusMsg = fmt.Sprintf("mirror to VAULT failed: %v", err)
				m.statusErr = true
			} else {
				m.statusMsg = fmt.Sprintf("added %s (mirrored to VAULT)", m.after.key)
			}
		}
		if m.after.editKey != "" && msg.err == nil {
			m.statusMsg = fmt.Sprintf("updated %s (VAULT — deployments unchanged; push to propagate)", m.after.editKey)
		}
		m.after = afterExec{}
		m.reload()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	switch m.mode {
	case modeFilter:
		return m.handleFilterKey(msg)
	case modeAddName, modeAddDesc:
		return m.handleAddKey(msg)
	case modeConfirm:
		return m.handleConfirmKey(msg)
	case modeSyncConflict:
		return m.handleSyncConflictKey(msg)
	case modeWipeConfirm:
		return m.handleWipeKey(msg)
	case modeGroupAssign:
		return m.handleGroupAssignKey(msg)
	}

	m.statusMsg, m.statusErr = "", false

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		// esc first backs out of a drilled-in group; otherwise quits.
		if m.openGroup[m.active] != "" {
			m.openGroup[m.active], m.cursors[m.active] = "", 0
			return m, nil
		}
		return m, tea.Quit
	case "enter":
		return m.handleEnter()
	case "?", "h":
		m.showHelp = true
	case "/":
		m.mode = modeFilter
		m.filterActive = true
	case "tab", "l", "right":
		m.active = (m.active + 1) % 3
	case "shift+tab", "left":
		m.active = (m.active + 2) % 3
	case "j", "down":
		if list := m.rows(m.active); m.cursors[m.active] < len(list)-1 {
			m.cursors[m.active]++
		}
	case "k", "up":
		if m.cursors[m.active] > 0 {
			m.cursors[m.active]--
		}
	case "R":
		m.reload()
		m.statusMsg = "reloaded"
	case "s":
		return m, m.startCopyOrPush(panelVault)
	case "g":
		return m, m.startCopyOrPush(panelPublic)
	case "p":
		return m, m.startCopyOrPush(panelProject)
	case "S":
		return m, m.startMove(panelVault)
	case "G":
		return m, m.startMove(panelPublic)
	case "P":
		return m, m.startMove(panelProject)
	case "a", "n":
		m.startAdd()
	case "d":
		return m, m.startDelete()
	case "u":
		// Overloaded by context (like s/g/p/d): on a ▸ group header it ungroups,
		// on a key it updates that key's value in place (VAULT only).
		if r, ok := m.currentRow(); ok && r.group != "" {
			return m, m.startUngroup()
		}
		return m, m.startEdit()
	case "c":
		if k := m.selected(); k != nil {
			m.checkDrift(k.Name)
			m.statusMsg = m.driftText
			m.statusErr = len(m.driftBad) > 0
		}
	case "y":
		return m, m.startSync()
	case "v":
		m.doReveal()
	case "W":
		m.startWipe()
	}
	return m, nil
}

func (m model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filter, m.filterActive, m.mode = "", false, modeNormal
		m.clampCursors()
	case "enter":
		m.mode = modeNormal
		m.clampCursors()
	case "backspace":
		if len(m.filter) > 0 {
			m.filter = m.filter[:len(m.filter)-1]
			m.clampCursors()
		}
	case "ctrl+u":
		m.filter = ""
		m.clampCursors()
	case "ctrl+c":
		return m, tea.Quit
	default:
		if r := msg.Runes; len(r) > 0 {
			m.filter += string(r)
			m.clampCursors()
		}
	}
	return m, nil
}

func (m model) handleAddKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.mode, m.input = modeNormal, ""
		m.statusMsg = "add cancelled"
	case "enter":
		if m.mode == modeAddName {
			name := strings.TrimSpace(m.input)
			if !keyNameRe.MatchString(name) {
				m.statusMsg = "invalid key name (use lowercase a-z, 0-9, -)"
				m.statusErr = true
				return m, nil
			}
			if m.names[m.addTgt][name] {
				m.statusMsg = fmt.Sprintf("%s already exists in %s", name, labelFor(m.addTgt))
				m.statusErr = true
				return m, nil
			}
			m.addKey, m.input, m.mode = name, "", modeAddDesc
			return m, nil
		}
		// modeAddDesc → launch the interactive value entry on a real TTY.
		m.addDesc = strings.TrimSpace(m.input)
		m.mode, m.input = modeNormal, ""
		return m, m.launchAdd()
	case "backspace":
		if len(m.input) > 0 {
			m.input = m.input[:len(m.input)-1]
		}
	case "ctrl+u":
		m.input = ""
	default:
		if r := msg.Runes; len(r) > 0 {
			m.input += string(r)
		}
	}
	return m, nil
}

func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		p := m.pending
		m.mode = modeNormal
		switch p.kind {
		case "copy":
			return m, m.doCopy(p.key, p.desc, p.src, p.dst)
		case "move":
			return m, m.doMove(p.key, p.desc, p.src, p.dst)
		case "pushgroup":
			return m, m.doPushGroup(p.group, p.src, p.dst)
		case "del", "delgroup":
			return m, m.doDelete(p)
		}
	default:
		m.mode = modeNormal
		m.statusMsg = "cancelled"
	}
	return m, nil
}

// --- operations -----------------------------------------------------------

// startCopyOrPush routes s/g/p: on a group header it pushes the whole group, on a
// key it copies that one key.
func (m *model) startCopyOrPush(dst panel) tea.Cmd {
	if r, ok := m.currentRow(); ok && r.group != "" {
		return m.startPushGroup(r.group, dst)
	}
	return m.startCopy(dst)
}

// handleEnter drills into a group header, or opens the group-assign prompt for a
// key.
func (m model) handleEnter() (tea.Model, tea.Cmd) {
	r, ok := m.currentRow()
	if !ok {
		return m, nil
	}
	if r.group != "" {
		m.openGroup[m.active], m.cursors[m.active] = r.group, 0
		return m, nil
	}
	// group membership is managed only from the VAULT master; PUBLIC/PROJECT are
	// deployments, so assigning/removing a group there is disallowed.
	if m.active != panelVault {
		m.statusMsg, m.statusErr = "manage groups from VAULT (PUBLIC/PROJECT are deployments)", true
		return m, nil
	}
	// prefill with this key's current group, else the last group entered
	prefill := m.groupOf(r.key.Name)
	if prefill == "" {
		prefill = m.lastGroup
	}
	m.groupKey, m.input, m.mode = r.key.Name, prefill, modeGroupAssign
	return m, nil
}

// startPushGroup copies every member of a group that exists in the active store
// into dst, so the whole group lands together. Confirms if any member would be
// overwritten in dst.
func (m *model) startPushGroup(group string, dst panel) tea.Cmd {
	if dst == m.active {
		m.statusMsg, m.statusErr = "source and target are the same store", true
		return nil
	}
	if m.groupCount(m.active, group) == 0 {
		m.statusMsg, m.statusErr = fmt.Sprintf("group %s has no keys in %s", group, labelFor(m.active)), true
		return nil
	}
	for _, k := range m.keys[m.active] {
		if m.groupOf(k.Name) == group && m.names[dst][k.Name] {
			m.mode = modeConfirm
			m.pending = pending{kind: "pushgroup", group: group, src: m.active, dst: dst}
			return nil
		}
	}
	return m.doPushGroup(group, m.active, dst)
}

func (m *model) doPushGroup(group string, src, dst panel) tea.Cmd {
	var pushed, failed int
	for _, k := range m.keys[src] {
		if m.groupOf(k.Name) != group {
			continue
		}
		if err := m.copyKeyOp(k.Name, k.Desc, m.dirFor(src), m.dirFor(dst)); err != nil {
			failed++
			continue
		}
		pushed++
	}
	m.reload()
	if failed > 0 {
		m.statusMsg, m.statusErr = fmt.Sprintf("pushed %d of group %s → %s, %d failed", pushed, group, labelFor(dst), failed), true
	} else {
		m.statusMsg = fmt.Sprintf("pushed group %s (%d keys) → %s", group, pushed, labelFor(dst))
	}
	return nil
}

// handleGroupAssignKey resolves the group-assign prompt: a typed name adds/moves
// the key into that group (creating it if new) and propagates the key to the
// stores that already hold the group; an empty name removes the key from its
// current group.
func (m model) handleGroupAssignKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.mode, m.input = modeNormal, ""
		m.statusMsg = "cancelled"
	case "enter":
		name := strings.TrimSpace(m.input)
		key := m.groupKey
		m.mode, m.input = modeNormal, ""
		if name == "" {
			if g := m.groupOf(key); g != "" {
				m.removeFromGroup(key)
				if err := m.saveGroups(); err != nil {
					m.statusMsg, m.statusErr = "save groups failed: "+err.Error(), true
					return m, nil
				}
				m.reload()
				m.statusMsg = fmt.Sprintf("removed %s from group %s", key, g)
			} else {
				m.statusMsg = "no group name entered"
			}
			return m, nil
		}
		if !keyNameRe.MatchString(name) {
			m.statusMsg, m.statusErr = "invalid group name (use lowercase a-z, 0-9, -)", true
			return m, nil
		}
		m.assignGroup(key, name)
		m.lastGroup = name
		if err := m.saveGroups(); err != nil {
			m.statusMsg, m.statusErr = "save groups failed: "+err.Error(), true
			return m, nil
		}
		n, err := m.propagateGroupKey(key, name)
		if err != nil {
			m.reload()
			m.statusMsg, m.statusErr = fmt.Sprintf("added to %s, but propagate failed: %v", name, err), true
			return m, nil
		}
		m.reload()
		if n > 0 {
			m.statusMsg = fmt.Sprintf("added %s to group %s (enforced into %d store(s))", key, name, n)
		} else {
			m.statusMsg = fmt.Sprintf("added %s to group %s", key, name)
		}
	case "backspace":
		if len(m.input) > 0 {
			m.input = m.input[:len(m.input)-1]
		}
	case "ctrl+u":
		m.input = ""
	default:
		if r := msg.Runes; len(r) > 0 {
			m.input += string(r)
		}
	}
	return m, nil
}

func (m *model) startCopy(dst panel) tea.Cmd {
	if dst == m.active {
		m.statusMsg, m.statusErr = "source and target are the same store", true
		return nil
	}
	k := m.selected()
	if k == nil {
		return nil
	}
	if m.names[dst][k.Name] {
		m.mode = modeConfirm
		m.pending = pending{kind: "copy", key: k.Name, desc: k.Desc, src: m.active, dst: dst}
		return nil
	}
	return m.doCopy(k.Name, k.Desc, m.active, dst)
}

func (m *model) startMove(dst panel) tea.Cmd {
	if r, ok := m.currentRow(); ok && r.group != "" {
		m.statusMsg, m.statusErr = "move applies to a single key — use s/g/p to push a whole group", true
		return nil
	}
	if dst == m.active {
		m.statusMsg, m.statusErr = "source and target are the same store", true
		return nil
	}
	k := m.selected()
	if k == nil {
		return nil
	}
	// Moving deletes the source copy, which would desync a group — block it for
	// grouped keys (ungroup first, or push/delete the whole group).
	if g := m.groupOf(k.Name); g != "" {
		m.statusMsg, m.statusErr = fmt.Sprintf("%s is in group %s — moving would split the group; ungroup it first (u) or act on the whole group", k.Name, g), true
		return nil
	}
	if m.names[dst][k.Name] {
		m.mode = modeConfirm
		m.pending = pending{kind: "move", key: k.Name, desc: k.Desc, src: m.active, dst: dst}
		return nil
	}
	return m.doMove(k.Name, k.Desc, m.active, dst)
}

func (m *model) doCopy(key, desc string, src, dst panel) tea.Cmd {
	if err := m.copyKeyOp(key, desc, m.dirFor(src), m.dirFor(dst)); err != nil {
		m.statusMsg, m.statusErr = fmt.Sprintf("copy failed: %v", err), true
		return nil
	}
	m.statusMsg = fmt.Sprintf("copied %s → %s", key, labelFor(dst))
	m.reload()
	return nil
}

// doMove copies then removes the source copy (silent file-level delete).
// Copy-before-rm guarantees a failed move duplicates (safe) rather than loses.
func (m *model) doMove(key, desc string, src, dst panel) tea.Cmd {
	if err := m.copyKeyOp(key, desc, m.dirFor(src), m.dirFor(dst)); err != nil {
		m.statusMsg, m.statusErr = fmt.Sprintf("move aborted (copy failed, source intact): %v", err), true
		return nil
	}
	if _, err := deleteKeysFromStore(m.dirFor(src), map[string]bool{key: true}); err != nil {
		m.reload()
		m.statusMsg, m.statusErr = fmt.Sprintf("copied to %s but source delete failed: %v", labelFor(dst), err), true
		return nil
	}
	m.reload()
	m.statusMsg = fmt.Sprintf("moved %s → %s", key, labelFor(dst))
	return nil
}

func (m *model) startAdd() {
	m.mode, m.input, m.addTgt = modeAddName, "", m.active
	m.addKey, m.addDesc = "", ""
}

// launchAdd hands the value entry to agent-vault on a real TTY, then (if the
// target isn't the VAULT) mirrors the new key up so the master stays complete.
func (m *model) launchAdd() tea.Cmd {
	args := []string{"set", m.addKey}
	if m.addDesc != "" {
		args = append(args, "--desc", m.addDesc)
	}
	c := m.av(m.dirFor(m.addTgt), args...)
	if m.addTgt != panelVault {
		m.after = afterExec{mirror: true, key: m.addKey, desc: m.addDesc, srcDir: m.dirFor(m.addTgt)}
	}
	return tea.ExecProcess(c, func(err error) tea.Msg { return execFinishedMsg{err} })
}

// startEdit re-enters the value for the selected VAULT key on a real TTY,
// overwriting it in place. It reuses the same TTY handoff as add — the value is
// typed straight into `agent-vault set`, which overwrites an existing key and
// retains its desc, so no plaintext ever passes through keymaster's memory.
// VAULT-only: deployments are independent copies by convention (see CLAUDE.md),
// so editing the master never cascades — push (s/g/p) afterward to propagate.
func (m *model) startEdit() tea.Cmd {
	if m.active != panelVault {
		m.statusMsg, m.statusErr = "edit is VAULT-only — deployments are independent copies; edit here then push (s/g/p) to propagate", true
		return nil
	}
	k := m.selected()
	if k == nil {
		m.statusMsg, m.statusErr = "select a key to edit (not a group header)", true
		return nil
	}
	args := []string{"set", k.Name}
	if k.Desc != "" {
		args = append(args, "--desc", k.Desc)
	}
	m.after = afterExec{editKey: k.Name}
	c := m.av(m.vaultDir, args...)
	return tea.ExecProcess(c, func(err error) tea.Msg { return execFinishedMsg{err} })
}

// startDelete opens a confirm for deleting the row under the cursor. Scope is set
// by the pane: from VAULT a delete cascades everywhere (VAULT + PUBLIC + current
// PROJECT), since deployments are copies of the master; from a deployment pane it
// removes only that pane's copy and never touches the VAULT. A group header
// deletes all its member keys at the same scope.
func (m *model) startDelete() tea.Cmd {
	r, ok := m.currentRow()
	if !ok {
		return nil
	}
	if r.group != "" {
		m.pending = pending{kind: "delgroup", group: r.group, src: m.active}
	} else {
		// A group is all-or-nothing in a deployment: deleting one member's copy
		// from PUBLIC/PROJECT would desync that pane from the global definition.
		// Remove the whole group here (d on its header), or manage it from VAULT.
		if m.active != panelVault {
			if g := m.groupOf(r.key.Name); g != "" {
				m.statusMsg, m.statusErr = fmt.Sprintf("%s belongs to group %s — delete the whole group (d on its ▸ header) or manage it from VAULT", r.key.Name, g), true
				return nil
			}
		}
		m.pending = pending{kind: "del", key: r.key.Name, src: m.active}
	}
	m.mode = modeConfirm
	return nil
}

// deleteScope returns the stores a delete initiated from pane src touches: all
// three from VAULT, else just src.
func deleteScope(src panel) []panel {
	if src == panelVault {
		return []panel{panelVault, panelPublic, panelProject}
	}
	return []panel{src}
}

// doDelete performs a confirmed delete: silent file-level removal of the target
// key(s) from each store in scope. No TTY, no value ever decrypted. A VAULT
// cascade that empties a group lets reload's pruneGroups drop the now-memberless
// group definition automatically.
func (m *model) doDelete(p pending) tea.Cmd {
	keySet := map[string]bool{}
	if p.kind == "delgroup" {
		for _, k := range m.groups[p.group] {
			keySet[k] = true
		}
	} else {
		keySet[p.key] = true
	}
	total := 0
	for _, st := range deleteScope(p.src) {
		n, err := deleteKeysFromStore(m.dirFor(st), keySet)
		if err != nil {
			m.reload()
			m.statusMsg, m.statusErr = fmt.Sprintf("delete failed in %s: %v", labelFor(st), err), true
			return nil
		}
		total += n
	}
	m.openGroup[m.active] = "" // membership may have changed underfoot
	m.reload()
	everywhere := p.src == panelVault
	switch {
	case p.kind == "delgroup" && everywhere:
		m.statusMsg = fmt.Sprintf("deleted group %s everywhere (%d copies)", p.group, total)
	case p.kind == "delgroup":
		m.statusMsg = fmt.Sprintf("deleted group %s from %s (%d keys)", p.group, labelFor(p.src), total)
	case everywhere:
		m.statusMsg = fmt.Sprintf("deleted %s everywhere (%d copies)", p.key, total)
	default:
		m.statusMsg = fmt.Sprintf("deleted %s from %s", p.key, labelFor(p.src))
	}
	return nil
}

// startUngroup removes a group definition (keys are kept) — the "ungroup" action.
// Only valid on a group header, and only from VAULT since the definition is
// global (ungrouping from a deployment would drop it everywhere).
func (m *model) startUngroup() tea.Cmd {
	r, ok := m.currentRow()
	if !ok || r.group == "" {
		m.statusMsg, m.statusErr = "u ungroups — put the cursor on a ▸ group header", true
		return nil
	}
	if m.active != panelVault {
		m.statusMsg, m.statusErr = "ungroup from VAULT (the group definition is global)", true
		return nil
	}
	delete(m.groups, r.group)
	if err := m.saveGroups(); err != nil {
		m.statusMsg, m.statusErr = "save groups failed: "+err.Error(), true
		return nil
	}
	m.openGroup[m.active] = ""
	m.reload()
	m.statusMsg = fmt.Sprintf("ungrouped %s (keys kept)", r.group)
	return nil
}

// startSync pushes every key in the focused deployment pane up into the VAULT:
// keys not yet in VAULT are copied straight up; keys already in VAULT are
// fingerprint-compared and, if the values differ, queued for an override prompt.
func (m *model) startSync() tea.Cmd {
	if m.active == panelVault {
		m.statusMsg, m.statusErr = "sync runs from a PUBLIC/PROJECT pane → VAULT", true
		return nil
	}
	src := m.active
	var copied, conflicts []string
	for _, k := range m.keys[src] {
		if !m.names[panelVault][k.Name] {
			if err := m.copyKeyOp(k.Name, k.Desc, m.dirFor(src), m.vaultDir); err != nil {
				m.statusMsg, m.statusErr = "sync copy failed: "+err.Error(), true
				return nil
			}
			copied = append(copied, k.Name)
			continue
		}
		hSrc, e1 := m.valueHash(m.dirFor(src), k.Name)
		hVault, e2 := m.valueHash(m.vaultDir, k.Name)
		if e1 != nil || e2 != nil {
			continue // can't compare → leave VAULT untouched
		}
		if hSrc != hVault {
			conflicts = append(conflicts, k.Name)
		}
	}
	m.reload()
	if len(conflicts) > 0 {
		m.syncPanel, m.syncConflicts, m.syncIdx, m.mode = src, conflicts, 0, modeSyncConflict
		m.statusMsg = fmt.Sprintf("synced %d new; %d differ — resolve", len(copied), len(conflicts))
		return nil
	}
	m.statusMsg = fmt.Sprintf("synced %d new key(s) → VAULT; no value conflicts", len(copied))
	return nil
}

func (m model) handleSyncConflictKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.syncIdx >= len(m.syncConflicts) {
		m.mode = modeNormal
		return m, nil
	}
	key := m.syncConflicts[m.syncIdx]
	switch msg.String() {
	case "y":
		m.overrideVault(key)
		m.syncIdx++
	case "n":
		m.syncIdx++
	case "a": // override every remaining conflict
		for _, kk := range m.syncConflicts[m.syncIdx:] {
			m.overrideVault(kk)
		}
		m.syncIdx = len(m.syncConflicts)
	case "s", "esc", "ctrl+c": // skip the rest
		m.syncIdx = len(m.syncConflicts)
	}
	if m.syncIdx >= len(m.syncConflicts) {
		m.mode = modeNormal
		m.reload()
		m.statusMsg = "sync complete"
	}
	return m, nil
}

// overrideVault replaces the VAULT copy of key with the sync panel's value.
func (m *model) overrideVault(key string) {
	desc := ""
	for _, kk := range m.keys[m.syncPanel] {
		if kk.Name == key {
			desc = kk.Desc
			break
		}
	}
	if err := m.copyKeyOp(key, desc, m.dirFor(m.syncPanel), m.vaultDir); err != nil {
		m.statusMsg, m.statusErr = "override failed: "+err.Error(), true
	}
}

// startWipe begins a full wipe of the focused deployment store. The VAULT (the
// master library) can never be wiped. Requires the user to type the pane's label
// to confirm — no per-key TTY prompts.
func (m *model) startWipe() {
	if m.active == panelVault {
		m.statusMsg, m.statusErr = "VAULT is the master library — it cannot be wiped", true
		return
	}
	if !m.exists[m.active] || len(m.keys[m.active]) == 0 {
		m.statusMsg, m.statusErr = fmt.Sprintf("%s is already empty — nothing to wipe", labelFor(m.active)), true
		return
	}
	m.wipeTgt, m.input, m.mode = m.active, "", modeWipeConfirm
}

func (m model) handleWipeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.mode, m.input = modeNormal, ""
		m.statusMsg = "wipe cancelled"
	case "enter":
		if strings.TrimSpace(m.input) != labelFor(m.wipeTgt) {
			m.mode, m.input = modeNormal, ""
			m.statusMsg, m.statusErr = "name did not match — wipe cancelled", true
			return m, nil
		}
		n := len(m.keys[m.wipeTgt])
		tgt := m.wipeTgt
		if err := m.wipeStore(tgt); err != nil {
			m.mode, m.input = modeNormal, ""
			m.statusMsg, m.statusErr = fmt.Sprintf("wipe failed: %v", err), true
			return m, nil
		}
		m.mode, m.input = modeNormal, ""
		m.reload()
		m.statusMsg = fmt.Sprintf("wiped %d key(s) from %s", n, labelFor(tgt))
	case "backspace":
		if len(m.input) > 0 {
			m.input = m.input[:len(m.input)-1]
		}
	case "ctrl+u":
		m.input = ""
	default:
		if r := msg.Runes; len(r) > 0 {
			m.input += string(r)
		}
	}
	return m, nil
}

// deleteKeysFromStore removes the named keys from a store's vault.json in place,
// touching only the (still-encrypted) entries and metadata — no value is ever
// decrypted, so the never-reveal invariant holds. Each secret is independently
// AES-GCM encrypted with no whole-file MAC, so dropping an entry leaves the rest
// intact (verified). This is the sanctioned non-TTY delete path — agent-vault's
// own `rm` refuses to run without a TTY, which makes bulk/cascade deletes
// impossible through it. A missing store or key is a no-op. Returns #removed.
func deleteKeysFromStore(dir string, keys map[string]bool) (int, error) {
	path := filepath.Join(dir, "vault.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return 0, err
	}
	raw, ok := top["secrets"]
	if !ok {
		return 0, nil
	}
	var secrets map[string]json.RawMessage
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return 0, err
	}
	n := 0
	for k := range keys {
		if _, ok := secrets[k]; ok {
			delete(secrets, k)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	nb, err := json.Marshal(secrets)
	if err != nil {
		return 0, err
	}
	top["secrets"] = nb
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return 0, err
	}
	return n, nil
}

// reconcileProject removes PROJECT keys whose VAULT copy no longer exists — the
// "invalid symlink" cleanup. It runs at startup before the UI so a project vault
// that fell out of sync (its master key was deleted while this dir was closed)
// self-heals. Guarded: if the VAULT store is missing or empty we skip entirely,
// so a misconfigured/uninitialized vault never nukes a populated project.
func (m *model) reconcileProject() {
	if !m.exists[panelProject] || !m.exists[panelVault] || len(m.keys[panelVault]) == 0 {
		return
	}
	stale := map[string]bool{}
	for _, k := range m.keys[panelProject] {
		if !m.names[panelVault][k.Name] {
			stale[k.Name] = true
		}
	}
	if len(stale) == 0 {
		return
	}
	n, err := deleteKeysFromStore(m.projectDir, stale)
	if err != nil {
		m.statusMsg, m.statusErr = "project reconcile failed: "+err.Error(), true
		return
	}
	if n > 0 {
		m.reload()
		m.statusMsg = fmt.Sprintf("reconciled PROJECT: removed %d stale key(s) whose VAULT copy was gone", n)
	}
}

// wipeStore destroys a deployment store by shredding its secret-bearing files and
// removing the store directory. agent-vault re-inits the store on the next `set`,
// so a wiped pane simply reads as empty. Never called for the VAULT.
func (m *model) wipeStore(p panel) error {
	if p == panelVault {
		return fmt.Errorf("refusing to wipe VAULT")
	}
	dir := m.dirFor(p)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			shredFile(filepath.Join(dir, e.Name()))
		}
	}
	return os.RemoveAll(dir)
}

// --- view -----------------------------------------------------------------

func (m model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	if m.showHelp {
		return m.renderHelpScreen()
	}

	info := m.renderInfo(m.width)
	prompt := m.renderPrompt(m.width)
	status := m.renderStatus(m.width)

	panelWidth := (m.width - 4) / 3
	if panelWidth < 20 {
		panelWidth = 20
	}
	listHeight := m.height - lipgloss.Height(info) - lipgloss.Height(prompt) - 3
	if listHeight < 5 {
		listHeight = 5
	}

	vault := m.renderPanel(panelVault, "~/.config/keymasterpoe/agent-vault/vault", panelWidth, listHeight)
	public := m.renderPanel(panelPublic, "~/.agent-vault", panelWidth, listHeight)
	project := m.renderPanel(panelProject, "./.agent-vault", panelWidth, listHeight)

	panels := lipgloss.JoinHorizontal(lipgloss.Top, vault, " ", public, " ", project)
	return lipgloss.JoinVertical(lipgloss.Left, info, prompt, panels, status)
}

func (m model) renderPanel(p panel, subtitle string, width, listHeight int) string {
	isActive := m.active == p
	list := m.rows(p)
	total := len(m.keys[p])

	var color lipgloss.Color
	switch p {
	case panelVault:
		color = lipgloss.Color("214") // orange
	case panelPublic:
		color = lipgloss.Color("82") // green
	case panelProject:
		color = lipgloss.Color("141") // purple
	}

	border := lipgloss.NormalBorder()
	if isActive {
		border = lipgloss.ThickBorder()
	}

	center := func(fg lipgloss.Color, bold bool) lipgloss.Style {
		return lipgloss.NewStyle().Foreground(fg).Bold(bold).Width(width - 4).Align(lipgloss.Center)
	}
	header := center(color, true).Render(labelFor(p))
	sub := center(lipgloss.Color("243"), false).Render(subtitle)
	var countText string
	switch {
	case m.openGroup[p] != "":
		countText = fmt.Sprintf("▸ %s (%d)  esc back", m.openGroup[p], m.groupCount(p, m.openGroup[p]))
	case m.filterText() != "":
		countText = fmt.Sprintf("(%d shown / %d keys)", len(list), total)
	default:
		if ng := numGroups(list); ng > 0 {
			countText = fmt.Sprintf("(%d keys · %d groups)", total, ng)
		} else {
			countText = fmt.Sprintf("(%d keys)", total)
		}
	}
	count := center(lipgloss.Color("243"), false).Render(countText)

	visibleItems := listHeight - 4
	if visibleItems < 1 {
		visibleItems = 10
	}

	var items []string
	if p == panelProject && !m.exists[p] {
		hint := lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Width(width - 4).Align(lipgloss.Center)
		items = append(items,
			"",
			hint.Render("no project vault here —"),
			hint.Render("[a] add, or [g]/[p]/[s]"),
			hint.Render("a key here to create it"),
		)
	} else {
		scroll := 0
		cursor := m.cursors[p]
		if cursor >= scroll+visibleItems {
			scroll = cursor - visibleItems + 1
		}
		for i := scroll; i < len(list) && i < scroll+visibleItems; i++ {
			sel := isActive && i == cursor
			if list[i].group != "" {
				items = append(items, m.renderGroupRow(list[i].group, p, sel, width))
			} else {
				items = append(items, m.renderRow(*list[i].key, p, sel, width))
			}
		}
	}
	for len(items) < visibleItems {
		items = append(items, strings.Repeat(" ", width-4))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, header, sub, count, "", strings.Join(items, "\n"))
	return lipgloss.NewStyle().
		Border(border).BorderForeground(color).
		Width(width).Height(listHeight).Padding(0, 1).
		Render(content)
}

// numGroups counts the group-header rows in a rendered list.
func numGroups(list []rowItem) int {
	n := 0
	for _, r := range list {
		if r.group != "" {
			n++
		}
	}
	return n
}

// renderGroupRow draws a group header: a ▸ disclosure marker, the group name in
// the pane color, and how many member keys live in this store.
func (m model) renderGroupRow(group string, p panel, selected bool, width int) string {
	var color lipgloss.Color
	switch p {
	case panelVault:
		color = lipgloss.Color("214")
	case panelPublic:
		color = lipgloss.Color("82")
	default:
		color = lipgloss.Color("141")
	}
	count := fmt.Sprintf(" (%d)", m.groupCount(p, group))
	label := "▸ " + group
	textW := width - 4 - len([]rune(count))
	if r := []rune(label); len(r) > textW {
		label = string(r[:textW-1]) + "…"
	}
	style := lipgloss.NewStyle().Bold(true).Width(width - 4 - len([]rune(count)))
	if selected {
		style = style.Background(lipgloss.Color("236")).Foreground(lipgloss.Color("231"))
	} else {
		style = style.Foreground(color)
	}
	countStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	return style.Render(label) + countStyle.Render(count)
}

// renderRow draws one key with a 2-slot indicator prefix. Fixed color language:
// green = PUBLIC, purple = PROJECT, red = alarm. The VAULT is the library
// (holds keys, deployed to nothing); PUBLIC/PROJECT are peer deployments.
//
//   VAULT pane   : where is this library key deployed?  green ●=PUBLIC  purple ●=PROJECT
//   PUBLIC pane  : slot1 red ● = NOT backed up to VAULT · slot2 purple ● = also in PROJECT
//   PROJECT pane : slot1 red ● = NOT backed up to VAULT · slot2 green ●  = also in PUBLIC
//
// A trailing red ≠ appears on a row after `c` (check drift) when that store's
// value differs from the baseline. Reach dots (green/purple) mark presence, not
// value equality — use `c` to actually compare.
func (m model) renderRow(k Key, p panel, selected bool, width int) string {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("82"))   // PUBLIC
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("141")) // PROJECT
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	inVault := m.names[panelVault][k.Name]
	inPublic := m.names[panelPublic][k.Name]
	inProject := m.names[panelProject][k.Name]

	slot1, slot2 := " ", " "
	switch p {
	case panelVault:
		if inPublic {
			slot1 = green.Render("●")
		}
		if inProject {
			slot2 = purple.Render("●")
		}
	case panelPublic:
		if !inVault {
			slot1 = red.Render("●")
		}
		if inProject {
			slot2 = purple.Render("●")
		}
	case panelProject:
		if !inVault {
			slot1 = red.Render("●")
		}
		if inPublic {
			slot2 = green.Render("●")
		}
	}
	indicator := slot1 + slot2

	// on-demand drift marker for the checked key
	marker, markerW := "", 0
	if k.Name == m.driftKey && m.driftBad[p] {
		marker, markerW = " "+red.Render("≠"), 2
	}

	nameWidth := width - 6 - markerW
	name := k.Name
	if r := []rune(name); len(r) > nameWidth {
		name = string(r[:nameWidth-1]) + "…"
	}
	style := lipgloss.NewStyle().Width(nameWidth)
	if selected {
		style = style.Bold(true).Background(lipgloss.Color("236")).Foreground(lipgloss.Color("15"))
	} else {
		style = style.Foreground(lipgloss.Color("252"))
	}
	return indicator + style.Render(name) + marker
}

func (m model) renderInfo(width int) string {
	inner := width - 4
	if inner < 10 {
		inner = 10
	}
	var body string
	if r, ok := m.currentRow(); ok && r.group != "" {
		var where []string
		for i := 0; i < 3; i++ {
			if c := m.groupCount(panel(i), r.group); c > 0 {
				where = append(where, fmt.Sprintf("%s:%d", labelFor(panel(i)), c))
			}
		}
		nameStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
		meta := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).
			Render(fmt.Sprintf("group · %d member(s) · present in: %s", len(m.groups[r.group]), strings.Join(where, ", ")))
		hintText := "enter open · s/g/p push whole group"
		if m.active == panelVault {
			hintText += " · u ungroup · d delete keys everywhere"
		} else {
			hintText += " · d delete keys from this pane"
		}
		hint := lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(hintText)
		body = nameStyle.Render("▸ "+r.group) + "\n" + meta + "\n" + hint
		return lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("244")).
			Width(width - 2).Height(6).Padding(0, 1).
			Render(body)
	}
	if k := m.selected(); k == nil {
		body = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("(no key selected)")
	} else {
		desc := k.Desc
		if desc == "" {
			desc = "(no description)"
		}
		var in []string
		for i := 0; i < 3; i++ {
			if m.names[i][k.Name] {
				in = append(in, labelFor(panel(i)))
			}
		}
		nameStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
		descStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("202")).Width(inner).MaxHeight(2)
		metaText := "in: " + strings.Join(in, ", ")
		if g := m.groupOf(k.Name); g != "" {
			metaText += "    group: " + g
		}
		meta := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(metaText)
		if m.driftKey == k.Name && m.driftText != "" {
			c := lipgloss.Color("120") // green-ish: compared, no diff
			if len(m.driftBad) > 0 {
				c = lipgloss.Color("196") // red: values differ
			}
			meta += lipgloss.NewStyle().Foreground(c).Render("    " + m.driftText)
		}
		// Value line: revealed plaintext (keyed to this exact key+pane) or a
		// dim affordance. Truncated to the box width — the clipboard got the full
		// value; this is only a visual echo.
		var valLine string
		if m.revealKey == k.Name && m.revealPanel == m.active && m.names[m.active][k.Name] {
			shown := m.revealVal
			if r := []rune(shown); len(r) > inner-9 {
				shown = string(r[:inner-10]) + "…"
			}
			valLine = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("value: ") +
				lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("46")).Render(shown) +
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("  (copied)")
		} else {
			valLine = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).
				Render("value: •••••••  (v — reveal & copy to clipboard)")
		}
		body = nameStyle.Render(k.Name) + "\n" +
			descStyle.Render(desc) + "\n" + meta + "\n" + valLine
	}
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("244")).
		Width(width - 2).Height(6).Padding(0, 1).
		Render(body)
}

func (m model) renderPrompt(width int) string {
	style := lipgloss.NewStyle().Padding(0, 1).Width(width)
	label := func(s string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Render(s)
	}
	hint := func(s string) string {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(s)
	}
	cursor := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("█")

	switch m.mode {
	case modeFilter:
		return style.Render(label("filter: ") + m.filter + cursor + hint("  (enter apply · esc clear)"))
	case modeAddName:
		return style.Render(label(fmt.Sprintf("new key in %s — name: ", labelFor(m.addTgt))) + m.input + cursor + hint("  (a-z 0-9 -)"))
	case modeAddDesc:
		return style.Render(label(fmt.Sprintf("%s — description: ", m.addKey)) + m.input + cursor + hint("  (enter → set value on TTY · esc cancel)"))
	case modeConfirm:
		var q string
		switch m.pending.kind {
		case "copy":
			q = fmt.Sprintf("overwrite %s in %s?", m.pending.key, labelFor(m.pending.dst))
		case "move":
			q = fmt.Sprintf("overwrite %s in %s and remove from %s?", m.pending.key, labelFor(m.pending.dst), labelFor(m.pending.src))
		case "pushgroup":
			q = fmt.Sprintf("push group %s → %s overwrites existing member keys there?", m.pending.group, labelFor(m.pending.dst))
		case "del":
			if m.pending.src == panelVault {
				q = fmt.Sprintf("delete %s EVERYWHERE (VAULT + PUBLIC + PROJECT)?", m.pending.key)
			} else {
				q = fmt.Sprintf("delete %s from %s only?", m.pending.key, labelFor(m.pending.src))
			}
		case "delgroup":
			n := len(m.groups[m.pending.group])
			if m.pending.src == panelVault {
				q = fmt.Sprintf("delete group %s (%d keys) EVERYWHERE?", m.pending.group, n)
			} else {
				q = fmt.Sprintf("delete group %s (%d keys) from %s only?", m.pending.group, n, labelFor(m.pending.src))
			}
		}
		warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q)
		return style.Render(warn + hint("  (y/n)"))
	case modeSyncConflict:
		if m.syncIdx < len(m.syncConflicts) {
			key := m.syncConflicts[m.syncIdx]
			q := fmt.Sprintf("%s differs (%s ≠ VAULT) — override VAULT? [y] yes · [n] no · [a] all · [s] skip-all", key, labelFor(m.syncPanel))
			warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q)
			return style.Render(warn + hint(fmt.Sprintf("  (%d/%d)", m.syncIdx+1, len(m.syncConflicts))))
		}
	case modeWipeConfirm:
		lbl := labelFor(m.wipeTgt)
		warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).
			Render(fmt.Sprintf("WIPE all %d key(s) from %s — type %s to confirm: ", len(m.keys[m.wipeTgt]), lbl, lbl))
		return style.Render(warn + m.input + cursor + hint("  (enter confirm · esc cancel)"))
	case modeGroupAssign:
		existing := make([]string, 0, len(m.groups))
		for g := range m.groups {
			existing = append(existing, g)
		}
		sort.Strings(existing)
		h := "  (enter: add/create · empty: remove from group · esc cancel)"
		if len(existing) > 0 {
			h = "  (groups: " + strings.Join(existing, " ") + ")"
		}
		return style.Render(label(fmt.Sprintf("group for %s: ", m.groupKey)) + m.input + cursor + hint(h))
	}
	if m.filterActive && m.filter != "" {
		return style.Render(label("filter: ") + m.filter + hint("  (/ edit · esc clear)"))
	}
	return ""
}

func (m model) renderStatus(width int) string {
	style := lipgloss.NewStyle().Padding(0, 1).Width(width)
	if m.statusMsg == "" {
		// idle: a quiet, single-line affordance instead of the old command bar.
		return style.Foreground(lipgloss.Color("243")).Render("h — help    esc — quit")
	}
	color := lipgloss.Color("82")
	if m.statusErr {
		color = lipgloss.Color("196")
	}
	return style.Foreground(color).Render(m.statusMsg)
}

func (m model) renderHelpScreen() string {
	lines := []string{
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Render("keymaster — help"),
		"",
		"  Three stores, side by side:",
		"    VAULT    private master library of every key (searchable, never exposed)",
		"    PUBLIC   ~/.agent-vault — the store agents pick up ambiently",
		"    PROJECT  ./.agent-vault — scoped to the current directory",
		"",
		"  Navigation",
		"    j / k / ↑ / ↓      move within a pane",
		"    tab / l / → · shift+tab / ← · switch pane (next / prev)",
		"    enter              open a group (drill in) · on a VAULT key: assign it to a group",
		"    esc                back out of an opened group (or quit)",
		"    /                  fuzzy-filter the focused pane (esc clears)",
		"",
		"  Groups (one global definition, shown in every pane that holds the keys)",
		"    A group collapses its keys under a ▸ header. Groups are MANAGED ONLY FROM VAULT —",
		"    PUBLIC/PROJECT are deployments. In VAULT, enter on a key names/creates a group for it",
		"    (empty name removes it); that also copies the key into every store already holding the",
		"    group, so a deployed group stays whole. In any pane, enter on a ▸ header drills in to view.",
		"    s / g / p on a ▸ header pushes the WHOLE group to VAULT / PUBLIC / PROJECT.",
		"    u on a ▸ header (VAULT only) UNGROUPS it — drops the group definition, keeps every key.",
		"",
		"  Keys (act on the selected entry)",
		"    s / g / p   COPY → VAULT / PUBLIC / PROJECT",
		"    S / G / P   MOVE → VAULT / PUBLIC / PROJECT (copy, then remove source)",
		"    y           SYNC the focused deployment pane → VAULT (backfill + resolve value conflicts)",
		"    c           CHECK drift: fingerprint-compare the selected key's value across stores",
		"    v           VIEW the selected key's value in the detail box AND copy it to the clipboard",
		"    a / n       ADD a new key here (also mirrored into VAULT)",
		"    d           DELETE (confirm y/n). From VAULT: deletes EVERYWHERE (VAULT+PUBLIC+PROJECT).",
		"                From PUBLIC/PROJECT: deletes that pane's copy only. On a ▸ header: all its keys.",
		"    u           On a key: UPDATE its value in place (VAULT only; re-typed on a TTY, deployments",
		"                stay independent — push s/g/p to propagate). On a ▸ header: UNGROUP (keeps keys).",
		"    W           WIPE every key from the focused deployment pane (PUBLIC/PROJECT only; type the",
		"                pane name to confirm). The VAULT master can never be wiped.",
		"    R           reload all panes    h / ?  this help    esc  quit",
		"",
		"  Indicators (left of each key) — the VAULT holds keys; PUBLIC/PROJECT are deployments:",
		"    VAULT row:     " + lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("●") + " deployed to PUBLIC   " +
			lipgloss.NewStyle().Foreground(lipgloss.Color("141")).Render("●") + " deployed to PROJECT   (none = held only)",
		"    PUBLIC/PROJECT: " + lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("●") + " NOT backed up to VAULT (press s or y)   " +
			lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("●") + "/" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("141")).Render("●") + " also deployed to the sibling store",
		"    " + lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("≠") + " (after `c`) the selected key's value DIFFERS across stores. Dots mark presence, not value.",
		"",
		"  Copying onto an existing key overwrites it (confirm first) — that's how you update the VAULT master.",
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("  `v` reveals a value (in the detail box + clipboard) — it briefly enters"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("  memory. Copy/move/drift never reveal; they relay via shredded temp files."),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("  press any key to return"),
	}
	body := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Padding(1, 2).Render(body)
}

// resolveAvBin finds the agent-vault CLI: PATH first, then the known pnpm path.
func resolveAvBin() (string, error) {
	if p, err := exec.LookPath("agent-vault"); err == nil {
		return p, nil
	}
	home, _ := os.UserHomeDir()
	pnpm := filepath.Join(home, ".local", "share", "pnpm", "agent-vault")
	if _, err := os.Stat(pnpm); err == nil {
		return pnpm, nil
	}
	return "", fmt.Errorf("agent-vault not found on PATH or at %s", pnpm)
}

func main() {
	avBin, err := resolveAvBin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keymaster: %v\n", err)
		fmt.Fprintln(os.Stderr, "install it with: pnpm add -g agent-vault")
		os.Exit(1)
	}
	p := tea.NewProgram(initialModel(avBin), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "keymaster: %v\n", err)
		os.Exit(1)
	}
}
