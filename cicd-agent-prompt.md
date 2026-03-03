# GitHub Actions CI/CD Agent Prompt
## `xero/lvthn` — Leviathan Cryptographic Library

---

## 🎯 Goal

Implement a tiered, waterfall-style GitHub Actions CI/CD pipeline for the **`xero/lvthn`** Leviathan cryptographic library. The pipeline must run the full vitest unit test suite and act as a **required PR gate** — blocking merges on any test failure.

---

## 📁 Repository Context

**Repo:** `xero/lvthn`
**Language:** TypeScript
**Test runner:** [vitest](https://vitest.dev/) `^3.2.4`
**Test command:** `npm test` (runs `vitest run`)
**Test config:** `vitest.config.ts`
**Test files location:** `test/spec/**/*.test.ts`

### Key constraints from `vitest.config.ts` that the workflow **must respect**:

- `testTimeout: 600000` — individual tests may run up to **10 minutes** (Monte Carlo tests: 400 × 10,000 iterations)
- `pool: "threads"` with `maxThreads: 1` / `minThreads: 1` — tests must run **sequentially**, single-threaded
- `sequence.concurrent: false` — test files run **one at a time**

### Test suite breakdown — 21 numbered spec files in `test/spec/`:

These are logically grouped and MUST be understood when deciding how to shard across workflow jobs:

| Group | Files | Description |
|-------|-------|-------------|
| **KAT / AES Core** | `01_kat.test.ts`, `02_intermediate.test.ts` | Known-Answer Tests, AES intermediate vectors |
| **Monte Carlo (CPU-heavy)** | `03_monte_carlo_ecb.test.ts`, `04_monte_carlo_cbc.test.ts` | 400×10k iteration Monte Carlo simulations — the longest-running tests |
| **Serpent** | `05_serpent_modes.test.ts`, `16_serpent.test.ts` | Serpent block cipher, all modes |
| **Serpent NESSIE** | `06_nessie_helpers.test.ts`, `07_nessie_vectors.test.ts`, `08_nessie128_vectors.test.ts` | NESSIE standard test vectors for Serpent |
| **Block mode / CTR** | `09_ctr_vectors.test.ts` | AES-CTR mode vectors |
| **Constant-time** | `10_constant_time.test.ts` | Side-channel / timing safety checks |
| **Argon2id** | `11_argon2id.test.ts` | Password hashing KAT vectors |
| **Base encoding** | `11_base.test.ts` | Base16/32/64 encoding utilities |
| **ChaCha20** | `12_chacha20.test.ts`, `12_chacha20poly1305.test.ts` | ChaCha20 and ChaCha20-Poly1305 AEAD |
| **HMAC** | `13_hmac.test.ts` | HMAC-SHA256/512 vectors |
| **Padding** | `14_padding.test.ts` | PKCS7, zero, ISO padding |
| **PBKDF2** | `15_pbkdf2.test.ts` | PBKDF2 key derivation vectors |
| **SHA-256** | `17_sha256.test.ts` | SHA-256 KAT vectors |
| **SHA-512** | `18_sha512.test.ts` | SHA-512 KAT vectors |
| **SHA-3 / SHAKE** | `19_sha3.test.ts` | SHA3-256, SHA3-512, SHAKE128, SHAKE256 |
| **UUID** | `20_uuid.test.ts` | UUID v4/v7 generation tests |
| **X25519 / Ed25519** | `21_x25519.test.ts` | Curve25519 ECDH and Ed25519 signature vectors |

There are also large inline vector files (e.g., `x25519_vectors.ts` at 1.6MB, `shake128_vectors_long.ts` at 333KB, `sha512_vectors.ts` at 206KB) — these are loaded by the test files, not run directly.

---

## 🏗️ Workflow Architecture

Model the structure after [`xero/text0wnz`'s waterfall test suite](https://github.com/xero/text0wnz/blob/main/.github/workflows/test-suite.yml), using **reusable called workflows** that execute in dependency order. Create the following files under `.github/workflows/`:

### 1. `.github/workflows/test-suite.yml` — Orchestrator (entry point)

- Triggers on:
  - `push` to `main`, with `paths-ignore` for `docs/**`, `**/*.md`, `LICENSE`, `.gitignore`, `.npmignore`
  - `pull_request` to `**` (all branches) — **this is the PR gate**
  - `workflow_dispatch` (manual trigger)
- Calls the child workflows in dependency/waterfall order:
  1. `build` — TypeScript compile check (no `needs`)
  2. `unit-fast` — fast unit tests (needs: `build`)
  3. `unit-heavy` — Monte Carlo + long-running tests (needs: `unit-fast`)
  4. `unit-crypto` — remaining crypto primitive tests (needs: `unit-fast`)
- Permissions: `contents: read`

### 2. `.github/workflows/build.yml` — TypeScript Build Check

- A standalone reusable workflow (`on: workflow_call`)
- Node.js setup (use `actions/setup-node@v4`, Node 20 LTS)
- `npm ci`
- `npx tsc -p ./src --noEmit` — type-check without emitting (validates the library compiles clean)
- Cache `~/.npm` using `actions/cache@v4` keyed on `package-lock.json` hash

### 3. `.github/workflows/unit-fast.yml` — Fast Unit Tests

- Reusable workflow (`on: workflow_call`)
- Node 20 LTS, `npm ci` with cache
- Run only the fast, deterministic spec files using vitest's `--reporter=verbose` and explicit file list:
  - `test/spec/01_kat.test.ts`
  - `test/spec/02_intermediate.test.ts`
  - `test/spec/11_base.test.ts`
  - `test/spec/12_chacha20.test.ts`
  - `test/spec/13_hmac.test.ts`
  - `test/spec/14_padding.test.ts`
  - `test/spec/15_pbkdf2.test.ts`
  - `test/spec/16_serpent.test.ts`
  - `test/spec/17_sha256.test.ts`
  - `test/spec/18_sha512.test.ts`
  - `test/spec/19_sha3.test.ts`
  - `test/spec/20_uuid.test.ts`
- Command: `npx vitest run --reporter=verbose test/spec/01_kat.test.ts test/spec/02_intermediate.test.ts ...` (list them all explicitly)
- `timeout-minutes: 30`

### 4. `.github/workflows/unit-heavy.yml` — Monte Carlo / Heavy Tests

- Reusable workflow (`on: workflow_call`)
- Node 20 LTS, `npm ci` with cache
- Run the CPU-heavy Monte Carlo simulations and NESSIE vector suites:
  - `test/spec/03_monte_carlo_ecb.test.ts`
  - `test/spec/04_monte_carlo_cbc.test.ts`
  - `test/spec/05_serpent_modes.test.ts`
  - `test/spec/06_nessie_helpers.test.ts`
  - `test/spec/07_nessie_vectors.test.ts`
  - `test/spec/08_nessie128_vectors.test.ts`
- These tests can individually take up to 10 minutes each (per `vitest.config.ts` `testTimeout: 600000`)
- `timeout-minutes: 90` — generous ceiling for the Monte Carlo simulations
- `runs-on: ubuntu-latest`

### 5. `.github/workflows/unit-crypto.yml` — Crypto Primitives

- Reusable workflow (`on: workflow_call`)
- Node 20 LTS, `npm ci` with cache
- Run the remaining crypto-heavy tests:
  - `test/spec/09_ctr_vectors.test.ts`
  - `test/spec/10_constant_time.test.ts`
  - `test/spec/11_argon2id.test.ts`
  - `test/spec/12_chacha20poly1305.test.ts`
  - `test/spec/21_x25519.test.ts`
- Note: `x25519_vectors.ts` is 1.6MB of inline vectors — the X25519 test may be slow
- `timeout-minutes: 60`

---

## ⚙️ Technical Requirements

- All jobs use **`ubuntu-latest`**
- Node.js **20 LTS** (`node-version: '20'`)
- Use **`npm ci`** (not `npm install`) for reproducible installs from `package-lock.json`
- Cache npm dependencies with `actions/cache@v4`:
  - key: `${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}`
  - restore-keys: `${{ runner.os }}-node-`
  - Alternatively use `actions/setup-node@v4`'s built-in `cache: 'npm'` option
- Use `actions/checkout@v4` in each child workflow
- All child workflows are **reusable** (`on: workflow_call`) and **only** called from the orchestrator
- The orchestrator `test-suite.yml` uses `uses: ./.github/workflows/<name>.yml` (local relative calls)
- Set `fail-fast: true` behavior via the `needs:` chain — if `build` fails, downstream jobs should not run
- Each workflow job should have `timeout-minutes` set appropriately to prevent runaway jobs
- Use `--reporter=verbose` for clear per-test output in CI logs
- Consider adding `--no-coverage` to skip any accidental coverage instrumentation in CI

---

## 🔒 PR Gate Configuration

After creating the workflow files, leave this instruction as a comment in `test-suite.yml`:

> After pushing these workflows, go to:
> **Settings → Branches → Branch protection rules** for `main`:
> - Enable **"Require status checks to pass before merging"**
> - Add these required checks:
>   - `build / build`
>   - `unit-fast / test`
>   - `unit-heavy / test`
>   - `unit-crypto / test`
> - Enable **"Require branches to be up to date before merging"**

This ensures all tiers of the test waterfall must pass before any PR can merge to `main`.

---

## 📝 Additional Notes

- **Do NOT modify** `vitest.config.ts` — the sequential/single-thread config is intentional for Monte Carlo accuracy and must be preserved
- **Do NOT modify** any test files or vector files in `test/spec/` or `test/vectors/`
- The `test/vectors/` directory contains large KAT vector `.txt` files (AES ECB/CBC, Serpent) read at test runtime — no special handling needed
- `argon2id` is a native `npm` dependency — it will compile from source on `npm ci`; `ubuntu-latest` has the required build tools by default
- The `package.json` `test` script (`vitest run`) runs ALL tests — do not use `npm test` in child workflows; call vitest directly with explicit file lists to achieve the tiered split
- Vitest CLI: `npx vitest run [files...]` supports listing files as positional arguments to run only those specific files
- The waterfall dependency chain is: `build` → `unit-fast` → (`unit-heavy` + `unit-crypto` in parallel)