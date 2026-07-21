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
- **Add** needs a real TTY (interactive value entry) → handed to `agent-vault set` via **`tea.ExecProcess`** (suspends the TUI, like launching `$EDITOR`). **Delete and move-rm are silent file-level ops** (`deleteKeysFromStore`, see recipe) — `agent-vault rm` can't be scripted, and editing `vault.json` touches only encrypted entries. Silent copy ops use plain `os/exec`.
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
- **Move** K src→dst: copy recipe, then delete K from src via the file-level delete below. **Never delete before `set` confirms success** — a failed move must duplicate (safe), never lose.
- **Add** K to store S: prompt for key name + desc in the TUI, then hand the *value* entry to `AGENT_VAULT_DIR=<S> agent-vault set K --desc '...'` via `tea.ExecProcess`. **If S ≠ VAULT, mirror into VAULT afterward** (silent Copy recipe, S→VAULT) so the master stays complete.
- **Update VAULT** (replace master with an edited project/public copy): the Copy recipe with dst=VAULT — `set` overwrites the existing master value. This is the "promote back up" flow; confirm first.
- **Edit value in place** (`startEdit`, `u` on a VAULT key): re-enter the selected VAULT key's value on a real TTY — reuses the Add TTY handoff (`AGENT_VAULT_DIR=<V> agent-vault set K --desc '<existing desc>'` via `tea.ExecProcess`), which overwrites the value and retains the desc, so no plaintext passes through keymaster's memory. **VAULT-only and does NOT cascade** — deployments are independent copies by convention, so push (`s`/`g`/`p`) afterward to propagate. Rejected on a deployment pane or a group header.
- **Delete** (`deleteKeysFromStore`): `agent-vault rm` refuses to run without a TTY (can't be piped), so it can't do bulk/cascade deletes. keymaster instead edits `<S>/vault.json` directly, dropping the key's entry from the `secrets` map. **This never decrypts a value** — each secret is independently AES-GCM encrypted (`iv:ciphertext:authtag`) with no whole-file MAC, so removing one entry leaves the rest intact (verified against v0.4.0). Scope by originating pane: **from VAULT it cascades to VAULT + PUBLIC + current PROJECT** (deployments are copies of the master); **from PUBLIC/PROJECT it removes only that pane's copy**, VAULT untouched. A single keymaster y/n confirm gates it (there is no longer an agent-vault prompt). A group header deletes all its member keys at the same scope; an emptied group definition is pruned on reload.
- **Reconcile PROJECT on startup** (`reconcileProject`, runs before the UI): removes any PROJECT key whose VAULT copy is gone — the "invalid symlink" cleanup for a project vault that fell out of sync while its dir was closed (keymaster only ever sees the *current* project, so cross-project deletes reconcile lazily on next open). Guarded: skips entirely when the VAULT store is missing or empty, so an uninitialized vault never nukes a populated project.
- **No reveal; in-place value edit only via the sanctioned TTY handoff** (`u` on a VAULT key — see Edit recipe; keymaster still never holds the plaintext). Cross-store *presence* is shown by reach dots (red ● = not backed up to VAULT); *value* comparison exists only on demand via external `sha256sum` fingerprints (`c` drift check, `y` sync) — a digest, never a revealed value.

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

**Delete scope rules** (`startDelete` → `modeConfirm` → `doDelete`, silent file-level delete):
- **From VAULT** → deletes EVERYWHERE (VAULT + PUBLIC + current PROJECT); deployments are copies of the master, so the master delete removes them too. Other project vaults reconcile on next open.
- **From PUBLIC/PROJECT** → deletes that pane's copy only; VAULT untouched.
- A `▸` group header deletes all its member keys at the same scope. `u` (VAULT only) instead *ungroups* — drops the group definition, keeps every key.

*(historical: the old `modeVDelete`/`rmQueue` orphan-protection modal and per-key TTY `rm` were replaced by the above once file-level delete landed.)*
- VAULT, deployed to **PROJECT** → `[v]` VAULT only (orphan project, allowed) or `[b]` both.
- VAULT, in both → `[b]` VAULT+PUBLIC (keep project) or `[a]` all three (public always goes with it).
- keymaster only sees the *current* project's `.agent-vault`; keys in other projects aren't tracked.

Keybindings: `tab`/`l`/`→` next pane · `shift+tab`/`←` prev pane · `j`/`k`/`↑↓` navigate · `enter` open group / assign key to group (VAULT) · `/` filter · `s` copy/push→VAULT (also "update master") · `g` →PUBLIC · `p` →PROJECT · `S`/`G`/`P` **move** (copy then delete source) · `y` **sync** pane→VAULT · `c` **check** drift · `v` **view+copy** the selected value (opt-in reveal) · `a`/`n` add (auto-mirrors to VAULT) · `d` **delete** (VAULT = everywhere; deployment = that pane only; confirm y/n) · `u` context-overloaded — **update** a key's value in place (VAULT only, TTY re-entry) on a key, **ungroup** on a `▸` header · `W` **wipe** a deployment pane · `R` refresh · `h`/`?` help · `esc` quit (backs out of an opened group first). The bottom command bar was removed — help lives on the `h`/`?` screen; the footer is a quiet `h — help / esc — quit`. Copy/delete/move are silent; only `add` shells out on a TTY via `tea.ExecProcess`. Delete and overwrite-on-copy confirm in the TUI (y/n). **Reload all three panes after any mutation.**

## Groups (added 2026-07)

An optional organizing layer *on top of* the three stores — agent-vault itself has no groups. A **group** is a named set of key names; **one global definition** lives in `~/.config/keymasterpoe/groups.json` (`{"docuseal": ["docuseal-api-key", ...]}`) and is shown in every pane that holds ≥1 of its member keys. A key belongs to **at most one group**. Membership names are non-secret, so the registry is plain JSON (no value ever involved).

- **All group editing is VAULT-only.** VAULT is the master library; PUBLIC/PROJECT are deployments (conceptually symlinks of the vault's keys), so create/modify/remove of group membership and ungroup happen only in the VAULT pane. Deployment panes can *view* groups (drill in), *receive* a pushed group, and delete a group's keys from their own pane — nothing that edits the shared definition.
- **Display**: a pane collapses grouped keys under a `▸ <group> (n)` header (n = members present in *that* store), listed above the ungrouped keys. `enter` on a header drills in (the pane shows just that group's member keys); `esc` backs out — allowed in any pane. `enter` on a key opens the group-assign prompt **only in VAULT** (type a name to add/create, empty to remove — reassigning moves it, since it's one-group-per-key); on PUBLIC/PROJECT it's rejected.
- **Push a whole group**: `s`/`g`/`p` on a `▸` header copies *every* member present in the focused store to VAULT/PUBLIC/PROJECT at once (silent relay; confirms if it would overwrite existing members). `S`/`G`/`P` (move) stays key-only.
- **Enforcement / propagation** (`propagateGroupKey`): adding a key to a group copies it into VAULT (master completeness) **and into any deployment store — PUBLIC/PROJECT — that already holds the group**, so a deployed group never goes partial. It is *not* pushed into stores that don't already carry the group. This is the "maintain one group and enforce it across the stores it lives in" rule.
- **Ungroup** (`u`, `startUngroup`): on a `▸` header, VAULT only — deletes the group *definition*, keeps every key. From PUBLIC/PROJECT it's rejected (the definition is global). This is the old "disband," renamed and moved off `d` so it's never confused with deletion.
- **Delete a group** (`d` on a `▸` header): deletes the member *keys* (not just the grouping), at the pane's delete scope — everywhere from VAULT, this-pane-only from PUBLIC/PROJECT. See the Delete recipe.
- **Group consistency invariant — a deployed group is all-or-nothing.** A group's membership must match the global definition in every store that holds it, so you can't split it: deleting a *single* grouped-key copy from PUBLIC/PROJECT is **rejected** (delete the whole group via its header, or manage membership from VAULT), and **moving** a grouped key (`S`/`G`/`P`) is rejected from any pane (moving deletes the source copy → split). Ungroup (`u`) first if you really need to move/delete one member. Additive ops (copy/push a member into a pane) are always fine.
- **Pruning**: `reload` drops member names that no longer exist in any store and deletes emptied groups, and closes a drilled-in group that lost all its members. Group defs never hold secrets, so this is metadata-only bookkeeping.

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
