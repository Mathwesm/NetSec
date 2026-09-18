// @ts-check
"use strict";
const { spawn } = require("node:child_process");

/** @typedef {{filename:string,line:number,column:number,end_column:number}} Span */
/** @typedef {{label:string,type:string,span?:Span}} Completion */
/** @typedef {{code:string,message:string,span:Span,related?:Span|null}} Diagnostic */
/** @typedef {{diagnostics:Diagnostic[],completions:Completion[],symbols:Completion[]}} Analysis */

/** @param {unknown} value @returns {value is Record<string,unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
/** @param {unknown} value @returns {boolean} */
function isSpan(value) {
  return isRecord(value) && typeof value.filename === "string" &&
    ["line", "column", "end_column"].every(key =>
      typeof value[key] === "number" && Number.isInteger(value[key]) && value[key] >= 1);
}
/** @param {unknown} value @returns {boolean} */
function isCompletion(value) {
  return isRecord(value) && typeof value.label === "string" && typeof value.type === "string" &&
    (value.span === undefined || isSpan(value.span));
}
/** @param {unknown} value @returns {Analysis} */
function validate(value) {
  if (!isRecord(value) || !Array.isArray(value.diagnostics) || !Array.isArray(value.completions) ||
      !Array.isArray(value.symbols) || !value.completions.every(isCompletion) ||
      !value.symbols.every(isCompletion) || !value.diagnostics.every(item =>
        isRecord(item) && typeof item.code === "string" && typeof item.message === "string" &&
        isSpan(item.span) && (item.related == null || isSpan(item.related)))) {
    throw new Error("Invalid response from NetSec compiler");
  }
  return /** @type {Analysis} */ (/** @type {unknown} */ (value));
}

/**
 * Invoke the compiler with explicit arguments and a bounded protocol.
 * @param {string} command
 * @param {string[]} args
 * @param {string} cwd
 * @param {object} request
 * @param {number} timeout
 * @returns {Promise<Analysis>}
 */
function analyze(command, args, cwd, request, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args, "editor"], {
      cwd, shell: false, windowsHide: true,
      env: { ...process.env, PYTHONUTF8: "1" }
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("NetSec compiler timed out"));
    }, timeout);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", text => {
      output += text;
      if (Buffer.byteLength(output) > 4000000) {
        child.kill();
        clearTimeout(timer);
        reject(new Error("NetSec compiler response exceeded the size limit"));
      }
    });
    // Drain stderr to avoid blocking, without retaining source or environment values.
    child.stderr.on("data", () => {});
    child.on("error", error => { clearTimeout(timer); reject(error); });
    child.stdin.on("error", error => { clearTimeout(timer); reject(error); });
    child.on("close", code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error("NetSec compiler exited with code " + code));
      try { resolve(validate(JSON.parse(output))); } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

/** @param {string} text @param {number} character @returns {number} */
function codepointColumn(text, character) {
  return Array.from(text.slice(0, character)).length + 1;
}
/** @param {string} text @param {number} column @returns {number} */
function utf16Character(text, column) {
  return Array.from(text).slice(0, Math.max(0, column - 1)).join("").length;
}

module.exports = { analyze, validate, codepointColumn, utf16Character };
