"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { imports, bundle } = require("../modules");

test("Import discovery ignores comments and string contents", () => {
  assert.deepEqual(imports('// import "ignored.netsec";\nreport "import hidden"; import "lib/types.netsec";'), ["lib/types.netsec"]);
});

test("Module bundles reject traversal and resolve shared imports once", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "netsec-modules-"));
  await fs.writeFile(path.join(root, "types.netsec"), "class Server { port management; }", "utf8");
  const result = await bundle(path.join(root, "main.netsec"), 'import "types.netsec"; import "types.netsec"; import "../private.netsec";');
  assert.deepEqual(Object.keys(result), ["types.netsec"]);
  assert.match(result["types.netsec"], /class Server/);
});
