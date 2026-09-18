"use strict";
const assert = require("node:assert/strict");
const vscode = require("vscode");

async function run() {
  const extension = vscode.extensions.getExtension("Mathwesm.netsec-language");
  assert.ok(extension, "NetSec extension must be discovered");
  await extension.activate();
  const text = 'port admin = port(22);\ngroup servers { host "one" address "192.0.2.10"; }\nplay "audit" targets servers {\n    check port admin protocol tcp;\n}';
  const document = await vscode.workspace.openTextDocument({ language: "netsec", content: text });
  await vscode.window.showTextDocument(document);
  const position = new vscode.Position(3, 18);
  const result = await vscode.commands.executeCommand("vscode.executeCompletionItemProvider",
    document.uri, position);
  assert.ok(result.items.some(item => item.label === "admin" && item.detail === "port"),
    "Compiler-provided typed completion must appear");
  const definitions = await vscode.commands.executeCommand("vscode.executeDefinitionProvider",
    document.uri, position);
  assert.equal(definitions[0].range.start.line, 0);

  const bad = await vscode.workspace.openTextDocument({language:"netsec",content:"int value = true;"});
  await vscode.window.showTextDocument(bad);
  await vscode.commands.executeCommand("netsec.validate");
  const diagnostics = vscode.languages.getDiagnostics(bad.uri);
  assert.equal(diagnostics[0].code, "E_TYPE");
  assert.equal(diagnostics[0].range.start.line, 0);
  assert.equal(diagnostics[0].range.start.character, 12);
  process.stdout.write("NetSec editor integration: typed completion, definition and diagnostic passed.\n");
}
module.exports = { run };
