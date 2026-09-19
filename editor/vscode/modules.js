// @ts-check
"use strict";
const fs = require("node:fs/promises");
const path = require("node:path");

/** @param {string} text @returns {string[]} */
function imports(text) {
  const tokens = text.match(/\/\/[^\n]*|"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z_0-9]*|[^\s]/g) || [];
  return tokens.flatMap((token, index) => {
    if (token !== "import" || !tokens[index + 1]?.startsWith('"')) return [];
    try { const name = JSON.parse(tokens[index + 1]); return typeof name === "string" ? [name] : []; }
    catch { return []; }
  });
}

/** @param {string} filename @param {string} text @returns {Promise<Record<string,string>>} */
async function bundle(filename, text) {
  /** @type {Record<string,string>} */
  const modules = {};
  if (!path.isAbsolute(filename)) return modules;
  const root = await fs.realpath(path.dirname(filename));
  const pending = [{ parent: "", text }];
  let size = text.length;
  while (pending.length) {
    const item = pending.pop();
    if (!item) break;
    for (const name of imports(item.text)) {
      if (!name || name.includes("\\") || name.includes(":") || name.startsWith("/")) continue;
      const key = path.posix.normalize(path.posix.join(path.posix.dirname(item.parent), name));
      if (key.startsWith("../") || !key.endsWith(".netsec") || Object.hasOwn(modules, key)) continue;
      if (Object.keys(modules).length >= 64) throw new Error("Project exceeds 64 imports");
      try {
        const target = await fs.realpath(path.join(root, key));
        const relative = path.relative(root, target);
        if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
        const stats = await fs.stat(target);
        if (!stats.isFile() || stats.size > 4000000) throw new Error("Import exceeds the file size limit");
        const content = (await fs.readFile(target, "utf8")).replace(/^\uFEFF/, "");
        size += content.length;
        if (size > 1000000) throw new Error("Project exceeds the source size limit");
        modules[key] = content;
        pending.push({ parent: key, text: content });
      } catch (error) {
        if (/** @type {NodeJS.ErrnoException} */(error).code === "ENOENT") continue;
        throw error;
      }
    }
  }
  return modules;
}

module.exports = { imports, bundle };
