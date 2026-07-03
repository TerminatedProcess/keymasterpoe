// keymaster — a cwd-aware TUI to manage agent-vault secrets across three stores:
// a private VAULT (master library), the ambient PUBLIC store, and the current
// PROJECT store. Mirrors the sibling `viewskills` TUI in shape.
//
// Security invariant (the whole point): plaintext secret values NEVER pass
// through this process. The Go code only ever handles file paths and key names.
// Values are relayed store→store through agent-vault-rendered 0600 temp files
// (shredded immediately), and there is NO reveal feature. See SPEC.md / CLAUDE.md.
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

// shredFile removes a temp file, preferring `shred -u` to scrub the bytes.
func shredFile(p string) {
	if _, err := exec.LookPath("shred"); err == nil {
		_ = exec.Command("shred", "-u", p).Run()
	}
	_ = os.Remove(p) // backstop in case shred failed or is absent
}

// --- state ----------------------------------------------------------------

func (m *model) reload() {
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

// dupCount reports in how many stores a key name appears.
func (m model) dupCount(name string) int {
	n := 0
	for i := 0; i < 3; i++ {
		if m.names[i][name] {
			n++
		}
	}
	return n
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
		m.startDelete()
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
		case "delete":
			c := m.av(m.dirFor(p.src), "rm", p.key)
			return m, tea.ExecProcess(c, func(err error) tea.Msg { return execFinishedMsg{err} })
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

func (m *model) startDelete() {
	k := m.selected()
	if k == nil {
		return
	}
	m.mode = modeConfirm
	m.pending = pending{kind: "delete", key: k.Name, src: m.active}
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

func (m model) renderRow(k Key, p panel, selected bool, width int) string {
	tag := ""
	if m.dupCount(k.Name) > 1 {
		tag = "⇄dup"
	}
	avail := width - 6
	name := k.Name
	maxName := avail - len(tag) - 1
	if maxName < 3 {
		maxName = 3
	}
	if len(name) > maxName {
		name = name[:maxName-1] + "…"
	}
	pad := avail - len([]rune(name)) - len([]rune(tag))
	if pad < 1 {
		pad = 1
	}
	tagStyled := lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render(tag)

	line := name + strings.Repeat(" ", pad) + tagStyled
	style := lipgloss.NewStyle().Width(width - 6)
	if selected {
		style = style.Bold(true).Background(lipgloss.Color("236")).Foreground(lipgloss.Color("15"))
	} else {
		style = style.Foreground(lipgloss.Color("252"))
	}
	return style.Render(line)
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
		metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Width(inner)
		body = nameStyle.Render(k.Name) + "\n" +
			descStyle.Render(desc) + "\n" +
			metaStyle.Render("in: "+strings.Join(in, ", "))
	}
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("244")).
		Width(width - 2).Height(5).Padding(0, 1).
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
		case "delete":
			q = fmt.Sprintf("delete %s from %s?", m.pending.key, labelFor(m.pending.src))
		case "copy":
			q = fmt.Sprintf("overwrite %s in %s?", m.pending.key, labelFor(m.pending.dst))
		case "move":
			q = fmt.Sprintf("overwrite %s in %s and remove from %s?", m.pending.key, labelFor(m.pending.dst), labelFor(m.pending.src))
		}
		warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")).Render(q)
		return style.Render(warn + hint("  (y/n)"))
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
		Render("jk/↑↓ nav  tab/hl panes  / filter  s/g/p copy→V/Pub/Proj  S/G/P move  a add  d delete  R reload  ? help  q quit")
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
		"    a / n       ADD a new key here (also mirrored into VAULT)",
		"    d           DELETE from the focused store only",
		"    R           reload all panes    ?  this help    q / esc  quit",
		"",
		"  A key in more than one store is tagged ⇄dup. Copying onto an existing",
		"  key overwrites it (confirm first) — that's how you update the VAULT master.",
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("  keymaster NEVER reveals a value. To view one, run"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("  `agent-vault get <key> --reveal` yourself, outside this tool."),
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
