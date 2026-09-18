// @ts-check
"use strict";
const vscode = require("vscode");
const client = require("./client");

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("netsec");
  const output = vscode.window.createOutputChannel("NetSec");
  /** @type {Map<string, NodeJS.Timeout>} */
  const timers = new Map();
  const selector = { language: "netsec" };
  context.subscriptions.push(diagnostics, output, {
    dispose() { for (const timer of timers.values()) clearTimeout(timer); }
  });

  /** @param {vscode.TextDocument} document @param {vscode.Position} position */
  async function analyze(document, position) {
    if (!vscode.workspace.isTrusted) throw new Error("Trust this workspace before running NetSec");
    const folder = vscode.workspace.getWorkspaceFolder(document.uri) ?? vscode.workspace.workspaceFolders?.[0];
    if (!folder) throw new Error("Open the NetSec project folder first");
    const config = vscode.workspace.getConfiguration("netsec", document.uri);
    return client.analyze(config.get("command", "poetry"), config.get("arguments", ["run", "netsec"]),
      folder.uri.fsPath, {
        text: document.getText(), filename: document.uri.fsPath || "<editor>",
        line: position.line + 1,
        column: client.codepointColumn(document.lineAt(position.line).text, position.character)
      });
  }

  /** @param {vscode.TextDocument} document @param {import("./client").Span} span */
  function range(document, span) {
    const line = Math.min(document.lineCount - 1, Math.max(0, span.line - 1));
    const text = document.lineAt(line).text;
    const start = client.utf16Character(text, span.column);
    const end = Math.max(start + 1, client.utf16Character(text, span.end_column));
    return new vscode.Range(line, start, line, end);
  }

  /** @param {vscode.TextDocument} document */
  async function refresh(document) {
    const version = document.version;
    try {
      const result = await analyze(document, new vscode.Position(0, 0));
      if (document.isClosed || document.version !== version) return;
      diagnostics.set(document.uri, result.diagnostics.map(item => {
        const diagnostic = new vscode.Diagnostic(range(document, item.span), item.message,
          vscode.DiagnosticSeverity.Error);
        diagnostic.code = item.code;
        diagnostic.source = "NetSec";
        if (item.related) {
          diagnostic.relatedInformation = [new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range(document, item.related)),
            "Previous conflicting declaration")];
        }
        return diagnostic;
      }));
    } catch (error) {
      output.appendLine(String(error));
    }
  }

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider(selector, {
      async provideCompletionItems(document, position) {
        const result = await analyze(document, position);
        return result.completions.map(item => {
          const completion = new vscode.CompletionItem(item.label,
            item.type === "keyword" ? vscode.CompletionItemKind.Keyword : vscode.CompletionItemKind.Variable);
          completion.detail = item.type;
          completion.sortText = (item.type === "keyword" ? "1" : "0") + item.label;
          return completion;
        });
      }
    }),
    vscode.languages.registerHoverProvider(selector, {
      async provideHover(document, position) {
        const word = document.getText(document.getWordRangeAtPosition(position));
        const result = await analyze(document, position);
        const symbol = result.symbols.find(item => item.label === word);
        if (symbol) return new vscode.Hover(new vscode.MarkdownString().appendCodeblock(
          symbol.type + " " + symbol.label, "netsec"));
        return undefined;
      }
    }),
    vscode.languages.registerDefinitionProvider(selector, {
      async provideDefinition(document, position) {
        const word = document.getText(document.getWordRangeAtPosition(position));
        const result = await analyze(document, position);
        const symbol = result.symbols.find(item => item.label === word);
        if (symbol?.span) return new vscode.Location(document.uri, range(document, symbol.span));
        return undefined;
      }
    }),
    vscode.workspace.onDidOpenTextDocument(document => {
      if (document.languageId === "netsec") void refresh(document);
    }),
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.document.languageId !== "netsec") return;
      const key = event.document.uri.toString();
      clearTimeout(timers.get(key));
      timers.set(key, setTimeout(() => { timers.delete(key); void refresh(event.document); }, 300));
    }),
    vscode.workspace.onDidCloseTextDocument(document => {
      const key = document.uri.toString();
      clearTimeout(timers.get(key));
      timers.delete(key);
      diagnostics.delete(document.uri);
    }),
    vscode.commands.registerCommand("netsec.validate", async () => {
      const document = vscode.window.activeTextEditor?.document;
      if (document?.languageId === "netsec") await refresh(document);
    })
  );
  for (const document of vscode.workspace.textDocuments) {
    if (document.languageId === "netsec") void refresh(document);
  }
}

module.exports = { activate };
