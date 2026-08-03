// Run axe-core against the built web console and fail on any serious or critical
// violation.
//
// This lives in CI rather than in a local dev loop for two reasons discovered by
// trying both: a headless browser gets OOM-killed on the maintainer's laptop
// (systemd-oomd), and the console's own CSP — connect-src 'self', the same rule
// that stops a crafted URL repointing the SOC's data source — correctly refuses
// to load an analysis library into the page.
//
// The bundle is a client-rendered SPA, so the page needs a moment to boot before
// there is anything to audit; auditing an empty shell would pass vacuously.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

// Resolve dependencies from the CALLER's working directory, not from this file's
// location. npm installs into whichever directory CI runs the install in, and
// `createRequire(import.meta.url)` would look next to this script instead —
// finding nothing.
const requireFromCwd = createRequire(pathToFileURL(join(process.cwd(), 'noop.js')));
const puppeteer = (await import(pathToFileURL(requireFromCwd.resolve('puppeteer')).href)).default;
const axeSource = readFileSync(requireFromCwd.resolve('axe-core'), 'utf8');

const url = process.argv[2];
if (!url) {
  console.error('usage: node axe-check.mjs <url>');
  process.exit(2);
}

const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.goto(url, { waitUntil: 'networkidle2' });

// Wait for the WASM shell to render something, so the audit is not vacuous.
await page.waitForSelector('.app', { timeout: 30_000 });
await new Promise((r) => setTimeout(r, 2000));

// addScriptTag, not evaluate: `evaluate` runs the source as an EXPRESSION, which
// depends on how the bundle happens to be wrapped. A script tag is the documented
// way to inject a library, and the local static server serving dist/ imposes no
// CSP of its own — unlike the deployed console, whose connect-src 'self' is what
// stops this check running against a live deployment.
await page.addScriptTag({ content: axeSource });
await page.waitForFunction(() => typeof window.axe !== 'undefined', {
  timeout: 15_000,
});

const results = await page.evaluate(async () =>
  await window.axe.run(document, { resultTypes: ['violations'] }),
);
await browser.close();

const blocking = results.violations.filter((v) =>
  ['serious', 'critical'].includes(v.impact),
);

for (const v of results.violations) {
  const line = `${v.impact ?? 'unknown'}  ${v.id}  (${v.nodes.length} node(s))  ${v.help}`;
  console.log(blocking.includes(v) ? `::error::${line}` : `::warning::${line}`);
}

console.log(
  `axe: ${results.violations.length} violation type(s), ${blocking.length} serious/critical`,
);
process.exit(blocking.length > 0 ? 1 : 0);
