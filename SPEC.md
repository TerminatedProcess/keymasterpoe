# keymaster — spec

**Status:** draft v1 · **Author:** (with Claude) · **Target:** standalone Go TUI (binary `keymaster`), sibling of `viewskills` in `~/work/ai/claudetools/keymasterpoe/`.
**One-liner:** A terminal UI to manage `agent-vault` secrets across **three** stores — a private **VAULT** (master library of every key), the ambient **PUBLIC** store, and the **current-project** store — moving/copying/adding/deleting keys between them, replacing the old browser-service `avapp`. It imposes the `skills-vault`/`viewskills` paradigm onto keys. **Never reveals a value** — it organizes key names and locations only.

---

## 1. Motivation

The current `avapp` is a **browser-based** vault editor (`vault-ui.mjs` served on a port) that:
- only ever operates on the **global** vault, and
- runs as a **service** (half-broken per `~/.config/fish/avapp.md`: missing file + port clash on 6400).

We want a **local, cwd-aware TUI** — no service, no port — that shows **GLOBAL ⇆ PROJECT** side by side and lets you shuffle keys between them. Same shape as `viewskills` (the skills TUI), so it feels familiar.

### Why not replace agent-vault itself?
A deep-research pass (3 independent agents) concluded: agent-vault's core property — *placeholder-in-file, real value on disk, nothing plaintext crosses the AI agent's stdout* — is **nearly unique**. `op inject` matches the mechanism but is SaaS-locked; SOPS/Infisical/OpenBao are storage/servers that leak plaintext on a naive read and rely on the same "constrain the agent" discipline agent-vault already enforces by default. **Verdict: keep agent-vault as the backend; build the TUI on top.** (Open risk: agent-vault upstream's maintenance level — worth a glance before investing.)

---

## 2. Background: the agent-vault backend

### 2.1 Stores
agent-vault keeps one encrypted store per directory: `<dir>/vault.json` (ciphertext) + `<dir>/vault.key` (key, mode 600).

| Tier | Path | Selected by | Role |
|---|---|---|---|
| **VAULT** (private master) | `~/.config/keymasterpoe/agent-vault/vault/` | `AGENT_VAULT_DIR=…` (explicit) | Complete, searchable library of **every** key across all projects + global. Private — nothing reads it ambiently; only keymaster points at it. Lets you find/reuse an existing key. |
| **PUBLIC** | `~/.agent-vault/` | default (no env) | The subset agents/tools pick up **ambiently**. |
| **PROJECT** | `<cwd>/.agent-vault/` | `AGENT_VAULT_DIR=<cwd>/.agent-vault` | Scoped to the current repo. |

**Critical:** the CLI does **not** auto-detect a project vault from cwd. Running `agent-vault list` inside a project still reads the **PUBLIC** (`$HOME/.agent-vault`) store. The TUI **must set `AGENT_VAULT_DIR` explicitly** for the VAULT and PROJECT panes. (Verified: `agent-vault` resolves the store via `AGENT_VAULT_DIR`, else `$HOME/.agent-vault`.)

**Paradigm vs. skills-vault (important):** skills-vault promotes by **symlink** — one master, zero drift. Keys **cannot** be symlinked (each store is a self-contained encrypted blob), so distribution is a **copy of the value** and each copy is thereafter **independent** — a project can edit its value without touching VAULT, and vice-versa. VAULT is master *by convention*, not by link. Sync is therefore explicit:
- **VAULT stays complete automatically** — adding a key to PUBLIC/PROJECT also mirrors it into VAULT.
- **Updating VAULT is manual** — copy a store's key onto VAULT to replace the master with that copy's current value ("promote back up"). `set` overwrites, so copying onto an existing key confirms first.
- `⇄dup` flags a shared key **name** only; values may already differ (can't tell without revealing).

### 2.2 CLI contract (verified by test in a throwaway `/tmp` vault)

| Command | Non-interactive? | Notes |
|---|---|---|
| `list [--json]` | ✅ | key names only |
| `has <keys...>` | ✅ | exit 0/1 |
| `write <file> --content '...<agent-vault:KEY>...'` | ✅ | **agent-safe**: substitutes real value into `<file>`. This is how we read a value without a human/agent seeing it. |
| `read <file>` | ✅ | inverse: shows file with values re-redacted to placeholders |
| `set <key> --stdin` | ✅ | writes value from stdin pipe/redirect |
| `set <key> --from-env VAR` | ✅ | writes value from env var |
| `set <key>` (no flag) | ❌ TTY | interactive prompt for the value |
| `set` (any form) | — | **auto-inits** the vault dir if missing |
| `get <key> --reveal [--force]` | ❌ **TTY always** | `--force` does *not* bypass; refuses non-TTY stdout **by design** (anti-exfiltration). Only way to show a value to a human. |
| `rm <key>` | ❌ TTY | no `--yes`/`--force` |
| `init` | ❌ TTY | not needed — `set` auto-inits |
| `import <file>` / `scan <file>` | (human-only; unverified) | bulk `.env` import; not needed for v1 |

**Design consequences:**
- **Relay a value between stores invisibly** → use `write` to a temp file, then `set --stdin` from it. Fully non-interactive; the value is never displayed.
- **Add a value** → `set <key>` (interactive prompt) in a real terminal.
- **Delete** → `rm` in a real terminal.
- **No reveal.** keymaster deliberately never calls `get --reveal`. Values are entered once at creation and never shown by this app again (see §5).

Add/delete need a TTY. A Bubble Tea app owns the terminal, so it hands the real TTY to those subprocesses via **`tea.ExecProcess`** (the same mechanism used to launch `$EDITOR`).

---

## 3. Goals / Non-goals

### Goals
- Three-pane VAULT / PUBLIC / PROJECT view scoped to `cwd`.
- Move / copy a key between any two stores (directional promotion).
- Search the VAULT to find/reuse an existing key.
- Add a new key (to the focused pane) — **auto-mirrored into VAULT** so the master stays complete.
- Update VAULT by replacing the master copy with a project/public copy ("promote back up").
- Delete a key from one store (with confirmation) without affecting other stores' copies.
- Create a store on demand (or implicitly on first push).
- **Never let plaintext pass through the TUI's own process memory** — values only ever live in agent-vault-managed temp files (shredded) or the real terminal.
- Zero background service, zero ports. Just a binary you run in a directory.

### Non-goals (v1)
- **Revealing a value.** keymaster never shows a secret value after creation — by design (see §5). Reveal stays a manual `agent-vault get --reveal` in the user's own terminal, outside this tool.
- Editing an existing value in place (delete + re-add outside the tool).
- Bulk `.env` import/export (stretch).
- Managing arbitrary vault dirs beyond VAULT + public + cwd.
- Any network/daemon/multi-user features.
- Solving runtime env-leak (`/proc/<pid>/environ`) — out of scope; agent-vault protects the file-rendering path only.

---

## 4. UX

### 4.1 Layout (mirrors `viewskills`' pane feel)
```
┌ keymaster ─ /home/dev/work/onboarding ─────────────────────────────────────────────────┐
│  VAULT (~/.config/keymasterpoe/agent-vault/vault)  │  PUBLIC (~/.agent-vault)    │  PROJECT (./.agent-vault) │
│  ───────────────────────────────────  │  ──────────────────────    │  ──────────────────────   │
│  coolify-api-token                    │  coolify-api-token   ⇄dup   │  secret-key               │
│▸ github-pat                           │  github-pat          ⇄dup   │  gmail-client-id          │
│  grok-api-key                ⇄dup     │  grok-api-key        ⇄dup   │  grok-api-key       ⇄dup  │
│  nvidia-api-key                       │  ovh-vps-password           │  telegram-bot-token       │
│  ...                                  │                             │  test-delete-me           │
│  55 keys                              │  11 keys                    │  23 keys                  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
 [tab] switch  [s]→vault [g]→public [p]→project  (SHIFT=move)  [a]dd  [d]elete  [/]filter  [?]help  [q]uit
```
- Header shows `cwd`. Each pane header shows its store path + count.
- Keys present in **more than one** store are tagged (e.g. `⇄dup`) so duplicated/misplaced secrets are obvious at a glance. (Values are not compared — can't, without revealing.)
- Focused pane highlighted; `▸` marks the selected row.
- **No project vault?** PROJECT pane renders a placeholder: *"no project vault at ./.agent-vault — press [a] to add a key or [g]/[p]/[s] to push one here (creates it)."*

### 4.2 Keybindings
Promotion is **directional** (three targets), like `viewskills`' `g`/`p`/`s`. Lowercase = copy, uppercase = move (copy then delete-from-source).

| Key | Action |
|---|---|
| `←/→`, `tab`, `h/l` | switch focused pane |
| `↑/↓`, `j/k` | navigate rows |
| `s` / `S` | **copy** / **move** selected key → VAULT (onto an existing key = "update master") |
| `g` / `G` | **copy** / **move** selected key → PUBLIC |
| `p` / `P` | **copy** / **move** selected key → PROJECT |
| `a` / `n` | **add** a new key to the focused pane (auto-mirrors into VAULT) |
| `d` | **delete** selected key from the focused store only (confirm modal) |
| `/` | fuzzy filter within focused pane (`sahilm/fuzzy`, like viewskills) |
| `R` | refresh all panes |
| `?` | help overlay |
| `q` / `esc` | quit |

No reveal, no in-place edit, no value diff. Destructive/interactive actions (`a`, `d`, and the `rm` half of a move) shell out on a TTY via `tea.ExecProcess` and get a confirmation step where they mutate; a plain copy is silent (`os/exec`). **Copying onto a key that already exists in the target overwrites it → confirm first** (this is the intended path for updating the VAULT master).

### 4.3 Flows / operation recipes

All `<V>` = `~/.config/keymasterpoe/agent-vault/vault` (private master), `<G>` = `$HOME/.agent-vault` (public), `<P>` = `$PWD/.agent-vault`. `AV="agent-vault"`. `src`/`dst` are any two of these.

**Reveal** — **not supported.** keymaster never shows a value. If a human needs to see one, they run `agent-vault get K --reveal` in their own terminal, outside the tool.

**Copy** `K` from `src` → `dst` — value never enters Go memory:
```sh
tmp="$(mktemp)"                                             # 0600
AGENT_VAULT_DIR=<src> agent-vault write "$tmp" --content '<agent-vault:K>'   # real value → tmp, agent-safe
AGENT_VAULT_DIR=<dst> agent-vault set K --stdin --desc '...' < "$tmp"        # non-interactive write
shred -u "$tmp"
```
Runs silently (no TTY needed) — can be a normal `exec.Command`, not `ExecProcess`. The Go code only ever handles the **path** `$tmp`, never the bytes. If `dst` vault doesn't exist, `set` auto-creates it. If `K` already exists in `dst`, `set` **overwrites** it — confirm first (this is how **Update VAULT** works: run Copy with `dst=<V>` to replace the master with a copy's current value).
- Preserve the description: take it from `list --json` (loaded for the pane already) and pass through `--desc`. **Not** from `get` — `get` needs a TTY even without `--reveal` (see §9.4).

**Move** `K` `src` → `dst`:
```sh
# copy recipe above, then:
AGENT_VAULT_DIR=<src> agent-vault rm K       # TTY → tea.ExecProcess (confirm happens here)
```

**Add** new key `K` to store `S` — human types the value, TUI never sees it:
```sh
# via tea.ExecProcess (real TTY), interactive prompt from agent-vault:
AGENT_VAULT_DIR=<S> agent-vault set K --desc '...'
# then, if S is not VAULT, mirror it up so the master stays complete (silent Copy recipe):
AGENT_VAULT_DIR=<S> agent-vault write "$tmp" --content '<agent-vault:K>'
AGENT_VAULT_DIR=<V> agent-vault set K --stdin --desc '...' < "$tmp"; shred -u "$tmp"
```
(Prompt for the *key name* + description in the TUI; hand off to `agent-vault set` for the *value*; the mirror step is silent.)

**Delete** `K` from `S` — removes only `S`'s copy; other stores (incl. VAULT) keep theirs:
```sh
AGENT_VAULT_DIR=<S> agent-vault rm K         # TTY → tea.ExecProcess
```

**Listing** each pane:
```sh
AGENT_VAULT_DIR=<V> agent-vault list      # vault (private master)
AGENT_VAULT_DIR=<G> agent-vault list      # public (or unset AGENT_VAULT_DIR — same store)
AGENT_VAULT_DIR=<P> agent-vault list      # project (empty/err if dir missing → render placeholder)
```

---

## 5. Security model

- **Plaintext never enters the TUI process.** Store-to-store relays go value→temp-file (via `write`) then file→`set --stdin`; the Go code passes file paths only. Add/delete are handed to `agent-vault` on the **real terminal** via `tea.ExecProcess`.
- **No reveal, ever.** keymaster has no code path that displays a value. Values are entered once at creation (into `agent-vault set` on a real TTY) and never shown by the tool again. Revealing is a manual, out-of-tool action.
- **Temp files:** `mktemp` mode 0600, `shred -u` immediately after use, and on a `defer`/cleanup path for error cases. Never under a git-tracked dir.
- **No logging of values.** Debug logs may include key *names* and store paths, never contents. No value in window title, status line, or crash dumps.
- **Confirmation** before `move`/`delete` (irreversible on the source).
- **Descriptions** are treated as non-secret (safe to display); only *values* are protected.
- **VAULT privacy:** the master store lives outside `~/.agent-vault`, so no agent/tool reads it ambiently — only keymaster, when explicitly pointed at it.
- Out of scope: process-env leakage, swap.

---

## 6. Tech stack & layout

Mirror `viewskills` (`~/work/ai/claudetools/viewskills/`):
- **Go 1.26**, `charmbracelet/bubbletea` v1.3.x, `bubbles` v1.0.0, `lipgloss` v1.1.0, `sahilm/fuzzy`.
- Single `main.go` is acceptable for v1 (viewskills is ~1040 LOC single file); split later if it grows.

```
~/work/ai/claudetools/keymasterpoe/     # repo dir is keymasterpoe; binary is keymaster
├── main.go
├── go.mod            # module keymaster
├── go.sum
├── CLAUDE.md         # project brief (decisions, agent-vault contract, test recipe)
├── SPEC.md           # this doc
├── .gitignore        # /keymaster (the built binary)
└── .git/
```

Model/Update/View Bubble Tea structure. Shell out to `agent-vault` via `os/exec` (silent ops) and `tea.ExecProcess` (TTY ops). Detect `agent-vault` on `PATH` at startup; error clearly if absent.

---

## 7. Build, install, cutover

- **Build:** `go build -o keymaster .` → install to `~/go/bin/` (where `viewskills` lives), or `go install`.
- **Command name:** binary is `keymaster`. Keep **`avapp`** as the invocation for muscle memory (optionally add a `keymaster`/`km` alias). Repoint the fish function:
  - Old: `avapp` in `~/.config/fish/conf.d/vault.fish` launches the `vault-ui.mjs` service on a port.
  - New: `avapp` → just execs `~/go/bin/keymaster` in the current dir. Remove the service/port logic; delete/retire `vault-ui.mjs` and the stale `~/.config/fish/avapp.md` handoff.
- Update the fish `AGENT VAULT` help block (`avlist`/`avapp`/`avimport`/...) to describe the new TUI.
- Keep `avlist`, `avimport`, etc. as-is unless we fold them in later.

---

## 8. Testing

- **Unit-ish:** run against a throwaway store to avoid touching real vaults:
  ```sh
  export AGENT_VAULT_DIR=/tmp/avtest-$$      # point a pane at a throwaway store
  printf 'dummy' | agent-vault set k1 --stdin
  # exercise copy/move/list/add/delete across dummy stores
  rm -rf /tmp/avtest-*
  ```
- **Real smoke test target:** the `onboarding` project vault already contains a junk key `test-delete-me` and cross-store dupes (`grok/groq/nvidia-api-key`) — perfect first real exercise (move the dupes to PUBLIC/VAULT, delete the junk). Do this *with* the user, since `rm`/`set` are their calls.
- Verify: no value ever appears in TUI output/logs (and there is no reveal path at all); temp files are shredded; stores auto-create on first push; dup-tagging is correct across all three panes.

---

## 9. Resolved against agent-vault v0.4.0 (verified) + open risks

**Verified during v1 build (throwaway `/tmp` store + `main_test.go`):**
1. ✅ **`set --stdin --desc`** retains the description.
2. ✅ **`set`** overwrites an existing key (this is the intended "update VAULT" path) and auto-inits a missing store dir.
3. ✅ **Copy round-trip is lossless** — value bytes are byte-identical after `write`→`set --stdin` (special chars, no trailing newline).
4. ❌ **CORRECTION to old §9.4:** `agent-vault get K` requires a TTY **even without `--reveal`** ("cannot be run programmatically"), so it can NOT be used to read a description non-interactively. **Descriptions come from `list --json`** (`{"keys":[{"key","desc"}]}`) instead — which keymaster already loads for names. The Copy/Move recipes carry the desc from that metadata.
5. ✅ **Move atomicity** — copy always precedes `rm`; a failed copy aborts with the source intact, a failed `rm` merely duplicates (safe). Implemented in `doMove`.
6. **`rm`** has no `--yes` flag; it runs on the real TTY via `tea.ExecProcess` (keymaster also shows its own y/n confirm first). No hang/misrender observed.

**Still open:**
- **agent-vault upstream maintenance** — OSS tool (~300 stars, possibly low-churn). If it dies: fork (permissive) or swap its storage backend to SOPS+age while keeping the placeholder layer.
- **Rename** — agent-vault has no rename; implement as copy-to-new-name + delete-old if added (stretch).

## 10. Future (post-v1)
- Rename, edit-value, `.env` import/export panes.
- Bulk reconcile helper: one-key action to sweep pre-existing `⇄dup` keys into VAULT (v1 already auto-mirrors on *add*; this backfills keys created before keymaster or outside it).
- Show descriptions inline / detail pane.
- Drift indicator when a key exists in multiple stores with different values (can't compare values safely without reveal — likely show "differs?" only via a hash agent-vault would need to expose; probably out of scope).
- Config for extra named vault dirs beyond vault+public+cwd.
