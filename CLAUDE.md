# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status: v1 implemented

`main.go` (~840 LOC single-file, mirrors `viewskills`) + `main_test.go` (6 tests, all pass) are in place and build/pass. Binary installs to `~/go/bin/keymaster`. `SPEC.md` is the design doc; this file captures the locked constraints. The fish `avapp` cutover (below) has **not** been done yet.

## What This Is

**keymasterpoe** (binary `keymaster`) — a cwd-aware terminal UI to manage [`agent-vault`](https://www.npmjs.com/package/agent-vault) secrets across **three stores** side by side. It imposes the sibling `skills-vault` / `viewskills` paradigm onto keys: one library pane plus two promotion targets. The point: stop hunting for keys — VAULT is the one place every key is listed, and you push copies out to where they're needed.

| Pane | Store path | Selected by | Role |
|---|---|---|---|
| **VAULT** (private master) | `~/.config/keymasterpoe/agent-vault/vault/` | explicit `AGENT_VAULT_DIR` | Complete, searchable library of **every** key across all projects + global. Private — nothing reads it ambiently; only keymaster points at it. Source of truth for "does a key like this already exist?" |
| **PUBLIC** | `~/.agent-vault/` | default (no env) | The subset agents/tools pick up **ambiently** (agent-vault's default store). |
| **PROJECT** | `<cwd>/.agent-vault/` | explicit `AGENT_VAULT_DIR` | Scoped to the current repo. |

### How this differs from skills-vault

`skills-vault` promotes by **symlink** (one master file, symlinked into GLOBAL/PROJECT — zero drift). **Keys cannot be symlinked** — each agent-vault store is a self-contained encrypted blob (`vault.json` + `vault.key`, mode 600). So:

- **Distribution = copy of the value**, not a link. Each store's copy is then **independent** — editing a project's value does NOT touch the VAULT copy, and vice-versa. VAULT is master **by convention**, not by link.
- **VAULT stays complete automatically:** adding a key to PUBLIC or PROJECT also mirrors it into VAULT (silent copy right after the interactive `set`), so the library never misses a key you created. Adding directly to VAULT needs no mirror.
- **Updating VAULT is manual and explicit:** copy a store's key onto VAULT (`s`/`S`) to replace the master with that copy's current value — this is how you "promote a project's edited value back up." Copying onto an existing key **overwrites** it → confirm first.
- Because copies are independent, keymaster shows **reach indicators**, never value comparisons (it can't — no reveal). The VAULT is a *library* (holds keys, deployed to nothing); PUBLIC/PROJECT are peer *deployments*. See the indicator language under Architecture.

## Build & Run

```bash
go build -o keymaster .    # compile
./keymaster                # run in the directory whose project vault you want
```

Install to `~/go/bin/` (where `viewskills` lives). Go 1.26; `charmbracelet/bubbletea` v1.3.x, `bubbles` v1.0.0, `lipgloss` v1.1.0, `sahilm/fuzzy`. Single `main.go` is fine for v1 (viewskills is ~1040 LOC single-file). Stack mirrors viewskills to reuse its patterns, but a TUI is the only hard requirement — not this exact stack. Detect `agent-vault` on `PATH` at startup; error clearly if absent (installed via pnpm at `~/.local/share/pnpm/agent-vault`).

## The security invariant (the whole point)

**Default posture: plaintext values do NOT pass through keymaster's own process memory.** After a key is created (value typed once into `agent-vault` on a real TTY), the app handles *file paths* and *key names* for all copy/move/add/delete/sync ops. Those never touch a secret byte.

**Two deliberate, opt-in relaxations** (user's own tool, user's call):
1. **`v` — view + copy** (added 2026-07). Reveals the selected key's value into the detail box and copies it to the system clipboard, mirroring the old `avlist -v`. This intentionally lets the plaintext enter keymaster's memory briefly (rendered via the sanctioned `agent-vault write` relay → 0600 temp → read → `shred -u`), held only until the next reload/`clearReveal`. It is keyed to a specific key+pane so it hides the instant you navigate away. Clipboard transit is via `wl-copy`/`xclip`/`xsel` stdin (no temp file). This is the ONE display path; everything else still never shows a value.
2. **Value comparison by fingerprint** (below) — drift/sync compare digests, never plaintext.

**Value comparison by fingerprint** (`valueHash`): drift-check (`c`) and sync (`y`) need to know if two stores' values differ. keymaster renders each value to a 0600 temp (the same sanctioned `agent-vault write` relay as copy) and hashes it with an **external `sha256sum`**, so plaintext enters *that* process, never keymaster's — keymaster holds only the one-way digest, compares, discards. No value is ever displayed or persisted. This keeps "never reveal" while softening "can't compare".

- **Move a value between stores** → never `get --reveal`. Use `agent-vault write <tmp> --content '<agent-vault:KEY>'` to render the real value into a 0600 temp file, then `agent-vault set KEY --stdin < tmp`. The value transits a shredded temp file only — never displayed, never in app memory. `shred -u` the temp immediately + on a `defer`/error path.
- **Add / delete / move-rm** need a real TTY → hand them to `agent-vault` via **`tea.ExecProcess`** (suspends the TUI, like launching `$EDITOR`). Silent copy ops use plain `os/exec`.
- Descriptions are non-secret (safe to display/capture). Only *values* are protected. No value in logs, status line, window title, or crash dumps.

## agent-vault CLI contract

Verified by test in a throwaway `/tmp` vault (SPEC §2.2):
- **Store is chosen only by `AGENT_VAULT_DIR`** — the CLI does NOT auto-detect a project vault from cwd. VAULT and PROJECT panes MUST set it explicitly; PUBLIC leaves it unset (defaults to `~/.agent-vault`).
- `list [--json]`, `has <keys>` — non-interactive.
- `write <file> --content '...<agent-vault:KEY>...'` — non-interactive; substitutes the real value into `<file>`. The agent-safe value-relay path. `read <file>` is the inverse (re-redacts).
- `list --json` returns `{"keys":[{"key":"…","desc":"…"}]}` — **this is the sole source of both names and descriptions** (desc omitted when absent). Names/descs are non-secret, safe to hold in memory.
- `set <key> --stdin --desc '…'` — non-interactive write; **retains the desc** (verified), **overwrites** an existing key (verified), and **auto-inits the vault dir if missing** (so first push to VAULT/PROJECT creates it; `init` is never needed).
- `set <key>` (no flag), `rm <key>` — **require a TTY** (both are "human only").
- `get <key>` — **requires a TTY *always*, even without `--reveal`** ("handles secret values, cannot run programmatically"). So the description CANNOT be read via `get`; it comes from `list --json`. keymaster never calls `get` at all (no reveal feature).

These were verified against agent-vault **v0.4.0** in a throwaway `/tmp` store (and by `main_test.go`). Note the correction vs. the original SPEC §9.4: descriptions come from `list --json`, not `get`.

## Key operation recipes

Promotion is directional (like viewskills' `g`/`p`/`s`), because there are three targets. `<V>`=`~/.config/keymasterpoe/agent-vault/vault`, `<G>`=`$HOME/.agent-vault` (public), `<P>`=`$PWD/.agent-vault`.

- **Copy** K src→dst: `AGENT_VAULT_DIR=<src> agent-vault write tmp --content '<agent-vault:K>'`, then `AGENT_VAULT_DIR=<dst> agent-vault set K --stdin --desc '...' < tmp`, then `shred -u tmp`. The `--desc` value comes from the already-loaded `list --json` metadata (NOT from `get`). Silent (`os/exec`). `set` **overwrites** if K already exists in dst → confirm before clobbering. Implemented in `copyKeyOp`.
- **Move** K src→dst: copy recipe, then `AGENT_VAULT_DIR=<src> agent-vault rm K` via `tea.ExecProcess`. **Never `rm` before `set` confirms success** — a failed move must duplicate (safe), never lose.
- **Add** K to store S: prompt for key name + desc in the TUI, then hand the *value* entry to `AGENT_VAULT_DIR=<S> agent-vault set K --desc '...'` via `tea.ExecProcess`. **If S ≠ VAULT, mirror into VAULT afterward** (silent Copy recipe, S→VAULT) so the master stays complete.
- **Update VAULT** (replace master with an edited project/public copy): the Copy recipe with dst=VAULT — `set` overwrites the existing master value. This is the "promote back up" flow; confirm first.
- **Delete**: `AGENT_VAULT_DIR=<S> agent-vault rm K` via `tea.ExecProcess` (confirm). Deletes only the copy in S — other stores' copies (incl. VAULT) are untouched.
- **No reveal, no in-place edit.** Cross-store *presence* is shown by reach dots (red ● = not backed up to VAULT); *value* comparison exists only on demand via external `sha256sum` fingerprints (`c` drift check, `y` sync) — a digest, never a revealed value.

## Architecture (planned — mirror viewskills' 3-panel layout)

Standard Bubble Tea `Init → Update → View`. **Three-pane** model (VAULT / PUBLIC / PROJECT), each with its own cursor + key list. Missing project vault → PROJECT pane shows a placeholder prompting a push to create it (first `set` auto-inits). `/` fuzzy-filters the focused pane. See `viewskills/main.go` for the pattern (panels, `tea.ExecProcess` for TTY handoff, reload-after-mutation).

**Indicator language** (`renderRow`, fixed colors: green=PUBLIC · purple=PROJECT · red=alarm). The VAULT is a *library* (holds keys, deployed to nothing); PUBLIC/PROJECT are peer *deployments*. Each row has a 2-slot prefix:
- **VAULT row** — where the key is deployed: green ● = PUBLIC, purple ● = PROJECT (no dot = held only, not deployed).
- **PUBLIC / PROJECT row** — slot1: **red ●** when the key is **not backed up to VAULT** (fix with `s` for one, or `y` to sync the whole pane). slot2: a dot when the key is **also deployed to the sibling** deployment (purple ● on PUBLIC = also in PROJECT; green ● on PROJECT = also in PUBLIC).
- **Trailing red ≠** — appears on a row after `c` (check drift) when that store's value *differs* from the baseline. Dots mark **reach** (presence); `≠` is the only value-equality signal, and only computed on demand.
- There is no "dup" tag; neither deployment is "the duplicate" — they're peers.

**Keymaster-owned actions beyond copy/move/add/delete:**
- `c` **check drift** — fingerprint-compares the selected key's value across the stores it's in (on-demand `valueHash`); verdict in the detail box + red `≠` on differing rows. Cleared on any reload.
- `y` **sync pane → VAULT** — backfills every not-in-VAULT key from the focused deployment pane; for keys already in VAULT, hash-compares and prompts (`modeSyncConflict`: y/n/all/skip) to override only the ones whose values differ.

**Delete scope rules** (`startDelete` → `modeVDelete` → sequential `rmQueue`, each `rm` its own TTY prompt):
- Deployment pane (PUBLIC/PROJECT) → deletes that copy only.
- VAULT, key not deployed → deletes it.
- VAULT, deployed to **PUBLIC** → can't orphan public: `[y]` delete both, or cancel (won't delete VAULT alone).
- VAULT, deployed to **PROJECT** → `[v]` VAULT only (orphan project, allowed) or `[b]` both.
- VAULT, in both → `[b]` VAULT+PUBLIC (keep project) or `[a]` all three (public always goes with it).
- keymaster only sees the *current* project's `.agent-vault`; keys in other projects aren't tracked.

Keybindings: `tab`/`h`/`l`/`←→` switch pane · `j`/`k`/`↑↓` navigate · `/` filter · `s` copy→VAULT (also "update master") · `g` copy→PUBLIC · `p` copy→PROJECT · `S`/`G`/`P` **move** (copy then rm source) · `y` **sync** pane→VAULT · `c` **check** drift · `v` **view+copy** the selected value (detail box + clipboard; opt-in reveal) · `a`/`n` add (auto-mirrors to VAULT) · `d` delete (scope rules above) · `R` refresh all · `?` help · `q`/`esc` quit. Copy is silent (`os/exec`); add/delete/move-rm shell out on a TTY via `tea.ExecProcess`. **Delete has no keymaster modal** — `agent-vault rm` prompts y/n on the TTY itself, so a second confirm would be redundant. Copying onto an existing key confirms (overwrite) in the TUI, since a plain copy is silent. **Reload all three panes after any mutation.**

## Testing

Never touch real vaults — use throwaway stores:
```sh
export AGENT_VAULT_DIR=/tmp/avtest-$$
printf 'dummy' | agent-vault set k1 --stdin
# exercise copy/move/list/add/delete across three fake stores
rm -rf /tmp/avtest-*
```
Verify: value never appears in TUI output/logs; temp files shredded; stores auto-create on first push; indicator logic correct (deploy dots on VAULT rows; red ● not-in-vault + cross-deploy dots on PUBLIC/PROJECT rows; red `≠` only after `c`); fingerprinting shells to external `sha256sum` and never holds plaintext; there is no code path that reveals a value. The `onboarding` project vault has real fixtures (`test-delete-me`, cross-store dupes `grok/groq/nvidia-api-key`) — exercise those *with the user*, since `rm`/`set` are their calls.

## Cutover (post-build)

Repoint the fish `avapp` function in `~/.config/fish/conf.d/vault.fish` to just exec `~/go/bin/keymaster` in cwd; drop the old service/port logic and retire `vault-ui.mjs` + the stale `~/.config/fish/avapp.md`. Keep `avlist`/`avimport` as-is.
