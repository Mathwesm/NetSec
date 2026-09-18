"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const client = require("../client");

test("Unicode source columns match VS Code UTF-16 offsets", () => {
  const text = 'report "😀"; invalid';
  const offset = text.indexOf("invalid");
  const column = client.codepointColumn(text, offset);
  assert.equal(column, offset);
  assert.equal(client.utf16Character(text, column), offset);
});
test("Malformed compiler payload cannot become editor diagnostics", () => {
  assert.throws(() => client.validate({diagnostics: [{message:"bad"}], completions:[], symbols:[]}),
    /Invalid response/);
});
test("Validated compiler diagnostics preserve conflict location", () => {
  const span = {filename:"demo.netsec",line:2,column:1,end_column:4};
  const response = client.validate({diagnostics:[{code:"E_TYPE",message:"Wrong type",span,related:span}],
    completions:[{label:"admin_port",type:"port",span}],symbols:[]});
  assert.equal(response.diagnostics[0].related.line, 2);
  assert.equal(response.completions[0].type, "port");
});
test("Missing compiler fails the request rather than returning an empty success", async () => {
  await assert.rejects(client.analyze("netsec-nonexistent-command-92345", [], process.cwd(), {}, 1000));
});
