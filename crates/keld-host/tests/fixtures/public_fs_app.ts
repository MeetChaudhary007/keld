// Prepared application imports only the public API index in its supplied prelude.
type FsSampleOutcome =
  | { ok: true; bytes: number[] }
  | { ok: false; code: string; message: string };
type Control = { action: string; nonce: string };
const base = "http://127.0.0.1:__PORT__";
const target = __TARGET__;
const outside = __OUTSIDE__;
const content = new Uint8Array(__CONTENT__);
const automaticComponent = __AUTOMATIC_COMPONENT__;
const naturalCase: "deny-read" | "links-limits" | null = __NATURAL_CASE__;
type NaturalInputs = {
  readSentinel: string;
  internalAlias: string;
  externalAlias: string;
  oversizedWrite: string;
  oversizedRead: string;
  fresh: string;
  maximumContent: number;
};
const naturalInputs: NaturalInputs | null = __NATURAL_INPUTS__;
const sampleControlBudget = 4096;
let handlerCalls = 0;
function rejectedFsOutcome(error: unknown): FsSampleOutcome {
  if (!isCallError(error)) throw error;
  // Preserve the registered native code and full original fix text.
  return { ok: false, code: error.code, message: error.message };
}
function isControl(value: unknown): value is Control {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().join(",") === "action,nonce" &&
    typeof record.action === "string" && typeof record.nonce === "string" &&
    /^[0-9a-f]{32}$/.test(record.nonce);
}
async function performFsOperation(action: "roundtrip" | "deny"): Promise<FsSampleOutcome> {
  try {
    if (action === "roundtrip") {
      await fs.write(target, content);
      return { ok: true, bytes: [...await fs.read(target)] };
    }
    await fs.write(outside, new Uint8Array([7, 8, 9]));
    return { ok: true, bytes: [] };
  } catch (error: unknown) {
    return rejectedFsOutcome(error);
  }
}
type NaturalAction =
  | "denied-read"
  | "internal-read" | "internal-write" | "internal-read-after-write"
  | "external-read" | "external-write"
  | "oversize-write" | "oversize-read"
  | "healthy-write" | "healthy-read";
async function performNaturalOperation(action: NaturalAction): Promise<FsSampleOutcome> {
  if (!naturalInputs) throw new Error("natural fixture inputs absent");
  try {
    switch (action) {
      case "denied-read":
        await fs.read(naturalInputs.readSentinel);
        // An unexpected allow is visible as success, but no sentinel data leaks.
        return { ok: true, bytes: [] };
      case "internal-read":
      case "internal-read-after-write":
        return { ok: true, bytes: [...await fs.read(naturalInputs.internalAlias)] };
      case "internal-write":
        await fs.write(naturalInputs.internalAlias, content);
        return { ok: true, bytes: [] };
      case "external-read":
        await fs.read(naturalInputs.externalAlias);
        return { ok: true, bytes: [] };
      case "external-write":
        await fs.write(naturalInputs.externalAlias, new Uint8Array([7, 8, 9]));
        return { ok: true, bytes: [] };
      case "oversize-write":
        await fs.write(naturalInputs.oversizedWrite,
          new Uint8Array(naturalInputs.maximumContent + 1).fill(0x79));
        return { ok: true, bytes: [] };
      case "oversize-read":
        await fs.read(naturalInputs.oversizedRead);
        // Never serialize an unexpectedly successful large read to the observer.
        return { ok: true, bytes: [] };
      case "healthy-write":
        await fs.write(naturalInputs.fresh, content);
        return { ok: true, bytes: [] };
      case "healthy-read":
        return { ok: true, bytes: [...await fs.read(naturalInputs.fresh)] };
    }
  } catch (error: unknown) {
    return rejectedFsOutcome(error);
  }
}
channels.handle(echoChannel, async request => {
  handlerCalls += 1;
  const control: unknown = JSON.parse(request.message);
  if (!isControl(control) || request.count !== handlerCalls) {
    throw new Error("public FS sample invalid action/nonce/count");
  }
  console.error("KELD_KEL140_PUBLIC_HANDLER " + JSON.stringify({
    call: handlerCalls, action: control.action, nonce: control.nonce, pid: process.pid,
  }));
  let outcome: FsSampleOutcome;
  if (control.action === "roundtrip" && request.count === 1) {
    outcome = await performFsOperation("roundtrip");
  } else if (control.action === "deny" && request.count === 2) {
    outcome = await performFsOperation("deny");
  } else {
    // Unrelated handler failures retain resolveEchoCall's existing API001 rule.
    throw new Error("public FS sample unknown action");
  }
  const response = { message: JSON.stringify(outcome), count: request.count };
  if (echoChannel.encodeResponse(response).byteLength > sampleControlBudget) {
    throw new Error("sample outcome exceeds renderer control budget");
  }
  console.error("KELD_KEL140_PUBLIC_OUTCOME " + JSON.stringify({
    call: handlerCalls, nonce: control.nonce, outcome,
  }));
  return response;
});
await app.whenReady();
if (process.env.KELD_DEV_LEASE !== undefined ||
    process.env.KELD_INTERNAL_MACOS_GUARDIAN_REGISTRATION !== undefined) {
  throw new Error("public FS application inherited host-only authority");
}
const descendant = Bun.spawn(["/usr/bin/tail", "-f", "/dev/null"], {
  stdin: "ignore", stdout: "ignore", stderr: "ignore",
});
const appLink = process.env.KELD_APP_LINK;
if (!appLink) throw new Error("public FS app has no host-minted link");
const ready = await fetch(base + "/observe", { method: "POST",
  headers: { "Content-Type": "text/plain" }, body: JSON.stringify({
    phase: "app-ready", pid: process.pid, descendantPid: descendant.pid,
    endpoint: appLink.slice(0, appLink.lastIndexOf("#")),
    executable: process.execPath, bunVersion: Bun.version,
  }),
});
if (!ready.ok) throw new Error("public FS ready observation refused");
if (automaticComponent) {
  // A public-main component: no renderer invoke, OS input or Echo forwarding.
  const outcomes: { action: "roundtrip" | "deny"; outcome: FsSampleOutcome }[] = [];
  for (const action of ["roundtrip", "deny"] as const) {
    outcomes.push({ action, outcome: await performFsOperation(action) });
  }
  const result = { phase: "app-result", pid: process.pid, componentOnly: true, outcomes };
  console.error("KELD_KEL140_PUBLIC_APP_COMPONENT " + JSON.stringify(result));
  const observed = await fetch(base + "/observe", { method: "POST",
    headers: { "Content-Type": "text/plain" }, body: JSON.stringify(result) });
  if (!observed.ok) throw new Error("public app component observation refused");
} else if (naturalCase) {
  // Closed public-main scenarios only: no renderer action or Echo forwarding.
  const actions: readonly NaturalAction[] = naturalCase === "deny-read"
    ? ["denied-read"]
    : ["internal-read", "internal-write", "internal-read-after-write",
      "external-read", "external-write", "oversize-write", "oversize-read",
      "healthy-write", "healthy-read"];
  const outcomes: { action: NaturalAction; outcome: FsSampleOutcome }[] = [];
  for (const action of actions) {
    outcomes.push({ action, outcome: await performNaturalOperation(action) });
  }
  const result = { phase: "app-result", pid: process.pid, componentOnly: true,
    naturalCase, outcomes };
  const body = JSON.stringify(result);
  if (new TextEncoder().encode(body).byteLength > sampleControlBudget) {
    throw new Error("natural outcomes exceed existing sample control budget");
  }
  console.error("KELD_KEL140_PUBLIC_APP_COMPONENT " + body);
  const observed = await fetch(base + "/observe", { method: "POST",
    headers: { "Content-Type": "text/plain" }, body });
  if (!observed.ok) throw new Error("public natural-case observation refused");
}
// The observer retains this stream without blocking other page observations.
const quit = await fetch(base + "/quit");
if (!quit.ok || await quit.text() !== "quit") throw new Error("invalid sample quit command");
console.error("KELD_KEL140_PUBLIC_QUIT_REQUEST calls=" + handlerCalls);
await app.quit();
process.exit(0);
