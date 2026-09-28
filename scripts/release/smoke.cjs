// Exercise real file capture, depfile decoding and child exit-code propagation.
// The helper is compiled for the target architecture; no mocked hooks or files.
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");
const assert = require("node:assert/strict");
const [root, target, probe] = process.argv.slice(2);
assert(probe, "native file I/O probe is required");
const exe = path.join(
  root,
  "bin/io-mon" + (target.startsWith("windows") ? ".exe" : ""),
);
const input = path.resolve("release-probe-input.txt");
const output = path.resolve("release-probe-output.txt");
const depfile = path.resolve("release-probe.rdep");
fs.writeFileSync(input, "release-input");
const capture = cp.spawnSync(
  exe,
  ["run", "--depfile", depfile, "--", probe, input, output],
  { encoding: "utf8", timeout: 30000 },
);
assert.equal(capture.status, 7, JSON.stringify(capture));
assert.equal(fs.readFileSync(output, "utf8"), "release-input-captured");
const decoded = cp.execFileSync(exe, ["inspect", depfile, "--format", "json"], {
  encoding: "utf8",
  timeout: 30000,
});
JSON.parse(decoded);
assert(decoded.includes("release-probe-input.txt"), decoded);
assert(decoded.includes("release-probe-output.txt"), decoded);
