// Node ESM loader hooks that let `node --test` import Vite's `?raw` specifiers
// (e.g. `../../../ADMIN_POLICY.md?raw`). Vite compiles those to a default string
// export; here we read the file and emit the equivalent module so the api/policy
// modules are loadable outside the bundler. Tests only — never used by the app.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const RAW_SUFFIX = '?raw';

export async function resolve(specifier, context, nextResolve) {
  if (specifier.endsWith(RAW_SUFFIX)) {
    const bare = specifier.slice(0, -RAW_SUFFIX.length);
    const resolved = new URL(bare, context.parentURL);
    // Keep the query so `load` knows this is a raw text import.
    return { url: `${resolved.href}${RAW_SUFFIX}`, format: 'module', shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url.endsWith(RAW_SUFFIX)) {
    const fileUrl = new URL(url);
    fileUrl.search = '';
    fileUrl.hash = '';
    const source = await readFile(fileURLToPath(fileUrl), 'utf8');
    return {
      format: 'module',
      shortCircuit: true,
      source: `export default ${JSON.stringify(source)};\n`,
    };
  }
  return nextLoad(url, context);
}
