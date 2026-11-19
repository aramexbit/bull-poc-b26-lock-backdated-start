# PoC for Bull.family bug bounty report B-26

## SDK `lock()`: schedule is checked only relatively — malicious server backdates `start` and the lock is fully vested at creation

**Report B-26** (K-735). SDK under test: `sdk-live.mjs` — the Bull SDK live
19 Nov 2026, sha256 `3c1319e1…`, 34,788 bytes
(`https://www.bull.family/sdk/bull.mjs`).

### The bug

The SDK states: *"Safety: the API server is not trusted with your wallet.
Every transaction it returns is checked before it is sent."* `lock()` does
check the vesting schedule — but only RELATIVELY:

```js
const near = (got, days) => Math.abs(Number(got) - Number(days || 0) * 86400) <= 3600;
if (!near(L.cliff - L.start, cliffDays) || !near(L.end - L.start, durationDays) || !near(L.step, stepDays) || (Number(startAt) > 0 && Number(L.start) !== Math.floor(Number(startAt))))
```

`cliff − start`, `end − start`, and `step` are compared against the
requested durations — but `start` itself is only checked when the caller
passes `startAt`. When `startAt` is not passed — exactly the SDK's own
docstring example (`bull.lock({ ..., cliffDays: 90, durationDays: 365,
stepDays: 30, locker })`, no `startAt`) — `start` is unconstrained. A
compromised/malicious server backdates `start` by 455 days: cliff−start is
still 90 days and end−start is still 365 days (all checks pass), but
`now >= end`, so the lock is FULLY VESTED at creation and the beneficiary
claims the full amount immediately.

**Measured (fresh Anvil):** P3 — `lock()` returned id 5 with NO error;
claimable at once 500; employee claimed +500 immediately (asked cliff 90
days). C0 (honest lock) — victim −500 exactly, claimable 0. Full lock
amount, uncapped in general.

### Why this is not a duplicate

**B-13** (report `a1766fd7d1`) was the schedule NEVER being verified at all
— the server could set cliff +10 years and end +100 years. The patch added
the relative checks quoted above, and B-13's exact mechanism is dead. What
lives here is a residue INSIDE that patch: relative checks that a backdated
`start` defeats. Different manipulation (backdating `start`, not inflating
cliff/end), different fix (pin `start ≈ now` when `startAt` is not passed).
Dedupe risk, stated honestly: MEDIUM — B-13's suggested fix did ask to
compare start/cliff/end/step, so the team may view this as a B-13 residue;
the counter-argument is that the patch itself drew the line at relative
checks and never implemented an absolute anchor for `start`.

### How to reproduce

Local Anvil chain 4663, mock Bull API, real SDK verbatim, mock locker — no
real funds, no mainnet, no Bull infrastructure. All keys are Anvil's public
throwaway test keys.

1. Start Anvil: `anvil --port 8547 --chain-id 4663`
2. In this directory: `npm install`, then `node run-poc.mjs` (case "K-735
   P3"; the same runner also covers K-711 P1/P2 and the K-712 trailing-data
   note, with control C0)

What the PoC does: victim calls `lock()` for 500 tokens with cliffDays 90 /
durationDays 365 and NO `startAt`; the mock API returns a `createLock` step
with `start = now − 455 days` (cliff−start = 90d, end−start = 365d); the real
SDK sends it and returns a lock id with NO ERROR. The beneficiary claims all
500 tokens immediately.

Forge tests (mock locker): `cd chain && forge test` — 11/11 green.

`poc-result.json` holds the measured results (`exploited: true` for K-735
P3).

### Suggested fix

In `lock()`, when `startAt` is not passed, verify `L.start ≈ now` (within
the same ±1-hour tolerance used by the relative checks) — or require
`startAt` from the caller.
