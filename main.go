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
	modeVDelete      // choosing scope for a VAULT delete of a deployed key
	modeSyncConflict // resolving per-key value overrides during a panel sync
)

// pending records an operation awaiting a y/n confirmation.
type pending struct {
	kind string // "copy" | "move" | "delete"
	key  string
	desc string
	src  panel
	dst  panel
}

// afterExec records work to run once a tea.ExecProcess subprocess returns —
// currently only the auto-mirror of a freshly-added key up into the VAULT.
type afterExec struct {
	mirror bool
	key    string
	desc   string
	srcDir string
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

	// sequential rm queue for a multi-store VAULT delete
	rmQueue []panel
	rmKey   string

	// panel → VAULT sync conflict resolution
	syncPanel     panel
	syncConflicts []string // keys in both panel and VAULT with differing values
	syncIdx       int

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
		cwd:        cwd,
		avBin:      avBin,
	}
	m.reload()
	return m
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
	m.clampCursors()
}

func (m *model) clampCursors() {
	for i := 0; i < 3; i++ {
		list := m.visible(panel(i))
		if m.cursors[i] >= len(list) {
			m.cursors[i] = max(0, len(list)-1)
		}
	}
}

func (m model) visible(p panel) []Key {
	all := m.keys[p]
	if m.filterText() == "" {
		return all
	}
	needle := strings.ToLower(m.filterText())
	out := make([]Key, 0, len(all))
	for _, k := range all {
		if strings.Contains(strings.ToLower(k.Name), needle) ||
			strings.Contains(strings.ToLower(k.Desc), needle) {
			out = append(out, k)
		}
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

func (m model) selected() *Key {
	list := m.visible(m.active)
	if len(list) == 0 {
		return nil
	}
	idx := m.cursors[m.active]
	if idx >= len(list) {
		idx = len(list) - 1
	}
	return &list[idx]
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
		m.after = afterExec{}
		// continue a multi-store VAULT delete, one `rm` (one TTY prompt) at a time
		if len(m.rmQueue) > 0 {
			return m, m.runRmQueue()
		}
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
	case modeVDelete:
		return m.handleVDeleteKey(msg)
	case modeSyncConflict:
		return m.handleSyncConflictKey(msg)
	}

	m.statusMsg, m.statusErr = "", false

	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	case "/":
		m.mode = modeFilter
		m.filterActive = true
	case "tab", "l", "right":
		m.active = (m.active + 1) % 3
	case "shift+tab", "h", "left":
		m.active = (m.active + 2) % 3
	case "j", "down":
		if list := m.visible(m.active); m.cursors[m.active] < len(list)-1 {
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
		return m, m.startCopy(panelVault)
	case "g":
		return m, m.startCopy(panelPublic)
	case "p":
		return m, m.startCopy(panelProject)
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
		}
	default:
		m.mode = modeNormal
		m.statusMsg = "cancelled"
	}
	return m, nil
}

// --- operations -----------------------------------------------------------

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

// doMove copies then removes the source copy. The rm needs a TTY, so it is
// handed to agent-vault via ExecProcess. Copy-before-rm guarantees a failed
// move duplicates (safe) rather than loses.
func (m *model) doMove(key, desc string, src, dst panel) tea.Cmd {
	if err := m.copyKeyOp(key, desc, m.dirFor(src), m.dirFor(dst)); err != nil {
		m.statusMsg, m.statusErr = fmt.Sprintf("move aborted (copy failed, source intact): %v", err), true
		return nil
	}
	m.statusMsg = fmt.Sprintf("moved %s → %s", key, labelFor(dst))
	c := m.av(m.dirFor(src), "rm", key)
	return tea.ExecProcess(c, func(err error) tea.Msg { return execFinishedMsg{err} })
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

// startDelete decides the scope of a delete. Deployment panes (PUBLIC/PROJECT)
// delete only their own copy. In the VAULT (the library), a deployed key can't
// be silently orphaned: a PUBLIC deployment forces delete-both-or-cancel; a
// PROJECT deployment offers vault-only or both. Each `rm` is a separate TTY
// prompt (agent-vault's own), sequenced via the rm queue.
func (m *model) startDelete() tea.Cmd {
	k := m.selected()
	if k == nil {
		return nil
	}
	m.rmKey = k.Name
	if m.active != panelVault {
		m.rmQueue = []panel{m.active}
		return m.runRmQueue()
	}
	inPublic := m.names[panelPublic][k.Name]
	inProject := m.names[panelProject][k.Name]
	if !inPublic && !inProject {
		m.rmQueue = []panel{panelVault}
		return m.runRmQueue()
	}
	m.mode = modeVDelete // deployed → ask for scope
	return nil
}

// runRmQueue pops the next store off rmQueue and hands its `rm` to a TTY.
// execFinishedMsg calls it again until the queue drains, then reloads.
func (m *model) runRmQueue() tea.Cmd {
	next := m.rmQueue[0]
	m.rmQueue = m.rmQueue[1:]
	c := m.av(m.dirFor(next), "rm", m.rmKey)
	return tea.ExecProcess(c, func(err error) tea.Msg { return execFinishedMsg{err} })
}

func (m model) handleVDeleteKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	inPublic := m.names[panelPublic][m.rmKey]
	inProject := m.names[panelProject][m.rmKey]
	k := msg.String()
	cancel := func() (tea.Model, tea.Cmd) {
		m.mode, m.statusMsg = modeNormal, "delete cancelled"
		return m, nil
	}
	if k == "esc" || k == "ctrl+c" || k == "n" {
		return cancel()
	}
	switch {
	case inPublic && inProject:
		switch k {
		case "b":
			m.rmQueue = []panel{panelPublic, panelVault} // keep project (orphan allowed)
		case "a":
			m.rmQueue = []panel{panelPublic, panelProject, panelVault}
		default:
			return cancel()
		}
	case inPublic:
		if k != "y" && k != "b" {
			return cancel()
		}
		m.rmQueue = []panel{panelPublic, panelVault}
	case inProject:
		switch k {
		case "v":
			m.rmQueue = []panel{panelVault}
		case "b":
			m.rmQueue = []panel{panelProject, panelVault}
		default:
			return cancel()
		}
	}
	m.mode = modeNormal
	return m, m.runRmQueue()
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
	help := m.renderHelpBar(m.width)

	panelWidth := (m.width - 4) / 3
	if panelWidth < 20 {
		panelWidth = 20
	}
	listHeight := m.height - lipgloss.Height(info) - lipgloss.Height(prompt) - 4
	if listHeight < 5 {
		listHeight = 5
	}

	vault := m.renderPanel(panelVault, "~/.config/keymasterpoe/agent-vault/vault", panelWidth, listHeight)
	public := m.renderPanel(panelPublic, "~/.agent-vault", panelWidth, listHeight)
	project := m.renderPanel(panelProject, "./.agent-vault", panelWidth, listHeight)

	panels := lipgloss.JoinHorizontal(lipgloss.Top, vault, " ", public, " ", project)
	return lipgloss.JoinVertical(lipgloss.Left, info, prompt, panels, status, help)
}

func (m model) renderPanel(p panel, subtitle string, width, listHeight int) string {
	isActive := m.active == p
	list := m.visible(p)
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
	countText := fmt.Sprintf("(%d keys)", len(list))
	if m.filterText() != "" {
		countText = fmt.Sprintf("(%d / %d keys)", len(list), total)
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
			items = append(items, m.renderRow(list[i], p, isActive && i == cursor, width))
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
		meta := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("in: " + strings.Join(in, ", "))
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
		}
		warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q)
		return style.Render(warn + hint("  (y/n)"))
	case modeVDelete:
		inPublic := m.names[panelPublic][m.rmKey]
		inProject := m.names[panelProject][m.rmKey]
		var q string
		switch {
		case inPublic && inProject:
			q = fmt.Sprintf("delete %s from VAULT — also in PUBLIC & PROJECT · [b] VAULT+PUBLIC (keep project) · [a] all three · [esc] cancel", m.rmKey)
		case inPublic:
			q = fmt.Sprintf("delete %s from VAULT — also in PUBLIC (can't orphan public) · [y] delete both · [esc] cancel", m.rmKey)
		case inProject:
			q = fmt.Sprintf("delete %s from VAULT — also in PROJECT · [v] VAULT only · [b] both · [esc] cancel", m.rmKey)
		}
		return style.Render(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q))
	case modeSyncConflict:
		if m.syncIdx < len(m.syncConflicts) {
			key := m.syncConflicts[m.syncIdx]
			q := fmt.Sprintf("%s differs (%s ≠ VAULT) — override VAULT? [y] yes · [n] no · [a] all · [s] skip-all", key, labelFor(m.syncPanel))
			warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q)
			return style.Render(warn + hint(fmt.Sprintf("  (%d/%d)", m.syncIdx+1, len(m.syncConflicts))))
		}
	}
	if m.filterActive && m.filter != "" {
		return style.Render(label("filter: ") + m.filter + hint("  (/ edit · esc clear)"))
	}
	return ""
}

func (m model) renderStatus(width int) string {
	style := lipgloss.NewStyle().Padding(0, 1).Width(width)
	if m.statusMsg == "" {
		return style.Render(" ")
	}
	color := lipgloss.Color("82")
	if m.statusErr {
		color = lipgloss.Color("196")
	}
	return style.Foreground(color).Render(m.statusMsg)
}

func (m model) renderHelpBar(width int) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("202")).Padding(0, 1).Width(width).
		Render("jk nav  tab panes  / filter  s/g/p copy  S/G/P move  y sync→V  c check  v view+copy  a add  d delete  R reload  ? help  q quit")
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
		"    tab / h / l / ← →  switch pane",
		"    /                  fuzzy-filter the focused pane (esc clears)",
		"",
		"  Keys (act on the selected entry)",
		"    s / g / p   COPY → VAULT / PUBLIC / PROJECT",
		"    S / G / P   MOVE → VAULT / PUBLIC / PROJECT (copy, then remove source)",
		"    y           SYNC the focused deployment pane → VAULT (backfill + resolve value conflicts)",
		"    c           CHECK drift: fingerprint-compare the selected key's value across stores",
		"    v           VIEW the selected key's value in the detail box AND copy it to the clipboard",
		"    a / n       ADD a new key here (also mirrored into VAULT)",
		"    d           DELETE — deployment pane: that copy only. VAULT: can't orphan PUBLIC (delete both",
		"                or cancel); PROJECT lets you keep or delete the deployment.",
		"    R           reload all panes    ?  this help    q / esc  quit",
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
