/** KEL-140 private test caller; its imports expose only the public API. */
import { app, fs, isCallError } from "../../../../../../packages/@keld/api/src/index.ts";

function report(key: string, value: string | number | boolean): void {
  console.log(`KELD_WL ${key}=${value}`);
}

const ready = app.whenReady();
const scenario = process.argv[2] ?? "retirement";
if (scenario !== "retirement" && scenario !== "reply-wins" && scenario !== "healthy" &&
    scenario !== "ring-fit" && scenario !== "ring-over") {
  throw new Error("invalid private public-FS fixture scenario");
}
const control: unknown = JSON.parse(await Bun.stdin.text());
if (typeof control !== "object" || control === null ||
    !("target" in control) || typeof control.target !== "string" ||
    !("lateTarget" in control) || typeof control.lateTarget !== "string") {
  throw new Error("invalid private public-FS fixture control");
}
await ready;
// This counts one public Promise handler, not wire ERRs or native syscall entries.
let settlements = 0;
const ringRead = scenario === "ring-fit" || scenario === "ring-over";
const pending = ringRead
  ? fs.read(control.target)
  : fs.write(control.target, new Uint8Array([116, 50]));
await pending.then(
  (bytes) => {
    settlements += 1;
    if (ringRead) {
      if (!(bytes instanceof Uint8Array)) throw new Error("public ring read returned no bytes");
      report("read-length", bytes.length);
      report("read-sha256", new Bun.CryptoHasher("sha256").update(bytes).digest("hex"));
    }
    report("call-returned", true);
  },
  (error: unknown) => {
    settlements += 1;
    if (!isCallError(error)) throw error;
    report("call-code", error.code);
    report("call-returned", false);
  },
);
if (scenario === "retirement") {
  try {
    await fs.write(control.lateTarget, new Uint8Array([108, 97, 116, 101]));
    throw new Error("post-retirement public write unexpectedly succeeded");
  } catch (error: unknown) {
    if (!isCallError(error)) throw error;
    report("after-code", error.code);
  }
} else if (scenario === "healthy") {
  const bytes = await fs.read(control.target);
  report("read-hex", Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""));
  report("read-returned", true);
}
report("settlements", settlements);
// No Quit, reconnect, or extra request in reply-wins/ring modes. Let the canonical
// Worker reach the parent's terminal EOF and flush diagnostics before natural exit.
