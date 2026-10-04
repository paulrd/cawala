// Registers the `?raw` loader hooks for `node --test`. Wired from the package
// `test` script via `--import ./test/loaders/register-raw.mjs`.

import { register } from 'node:module';

register('./raw-hooks.mjs', import.meta.url);
