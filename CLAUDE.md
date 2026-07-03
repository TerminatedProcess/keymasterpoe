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
- Because copies are independent, `⇄dup` flags only that two stores share a key **name**; the values may already differ (can't tell without revealing).

## Build & Run

```bash
go build -o keymaster .    # compile
./keymaster                # run in the directory whose project vault you want
```

Install to `~/go/bin/` (where `viewskills` lives). Go 1.26; `charmbracelet/bubbletea` v1.3.x, `bubbles` v1.0.0, `lipgloss` v1.1.0, `sahilm/fuzzy`. Single `main.go` is fine for v1 (viewskills is ~1040 LOC single-file). Stack mirrors viewskills to reuse its patterns, but a TUI is the only hard requirement — not this exact stack. Detect `agent-vault` on `PATH` at startup; error clearly if absent (installed via pnpm at `~/.local/share/pnpm/agent-vault`).

## The security invariant (the whole point)

**Plaintext values must NEVER pass through keymaster's own process memory, and keymaster NEVER reveals a value.** After a key is created (value typed once into `agent-vault` on a real TTY), this app only ever handles *file paths* and *key names*. There is **no reveal feature** — deliberately. The Go code touching a secret byte, or the app displaying a value, both defeat the reason the tool exists.

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
- **No reveal, no in-place edit, no value diff** — can't compare values without revealing, so a shared key across stores shows only `⇄dup`, never a value comparison.

## Architecture (planned — mirror viewskills' 3-panel layout)

Standard Bubble Tea `Init → Update → View`. **Three-pane** model (VAULT / PUBLIC / PROJECT), each with its own cursor + key list. Keys present in more than one store get a `⇄dup` tag. Missing project vault → PROJECT pane shows a placeholder prompting a push to create it (first `set` auto-inits). `/` fuzzy-filters the focused pane. See `viewskills/main.go` for the pattern (panels, `tea.ExecProcess` for TTY handoff, reload-after-mutation).

Keybindings (adapted from viewskills — directional promotion, no reveal/diff/edit): `tab`/`h`/`l`/`←→` switch pane · `j`/`k`/`↑↓` navigate · `/` filter · `s` copy→VAULT (also "update master") · `g` copy→PUBLIC · `p` copy→PROJECT · `S`/`G`/`P` **move** (copy then rm source) · `a`/`n` add (auto-mirrors to VAULT) · `d` delete (confirm) · `R` refresh all · `?` help · `q`/`esc` quit. Copy is silent (`os/exec`); add/delete/move-rm shell out on a TTY via `tea.ExecProcess`. Copying onto an existing key confirms (overwrite). **Reload all three panes after any mutation.**

## Testing

Never touch real vaults — use throwaway stores:
```sh
export AGENT_VAULT_DIR=/tmp/avtest-$$
printf 'dummy' | agent-vault set k1 --stdin
# exercise copy/move/list/add/delete across three fake stores
rm -rf /tmp/avtest-*
```
Verify: value never appears in TUI output/logs; temp files shredded; stores auto-create on first push; dup-tagging correct across all three panes; there is no code path that reveals a value. The `onboarding` project vault has real fixtures (`test-delete-me`, cross-store dupes `grok/groq/nvidia-api-key`) — exercise those *with the user*, since `rm`/`set` are their calls.

## Cutover (post-build)

Repoint the fish `avapp` function in `~/.config/fish/conf.d/vault.fish` to just exec `~/go/bin/keymaster` in cwd; drop the old service/port logic and retire `vault-ui.mjs` + the stale `~/.config/fish/avapp.md`. Keep `avlist`/`avimport` as-is.
