// Layout regression check across the viewports the console must survive.
//
// Deliberately NOT image-diffing. A pixel baseline needs a first blessed capture,
// re-blessing on every intentional change, and it fails loudly for reasons nobody
// can act on. What actually broke this console was structural and assertable: the
// sidebar was moved off-screen below 1000px with nothing to bring it back, and the
// top bar overflowed horizontally. So this asserts the invariants and saves
// screenshots as ARTIFACTS for a human to glance at, rather than as a gate.
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

// Resolve puppeteer from the caller's working directory — see axe-check.mjs.
const requireFromCwd = createRequire(pathToFileURL(join(process.cwd(), 'noop.js')));
const puppeteer = (await import(pathToFileURL(requireFromCwd.resolve('puppeteer')).href)).default;

const url = process.argv[2];
if (!url) {
  console.error('usage: node viewport-check.mjs <url>');
  process.exit(2);
}

// The four sizes the hardening pass was verified at.
const VIEWPORTS = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'tablet-portrait', width: 768, height: 1024 },
  { name: 'small-desktop', width: 1024, height: 768 },
  { name: 'desktop', width: 1440, height: 900 },
];

// Below this width the sidebar is a drawer and the toggle MUST exist; above it,
// the sidebar is permanent and the toggle must not be in the tab order.
const DRAWER_BREAKPOINT = 1000;

mkdirSync('screenshots', { recursive: true });
const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
const failures = [];

for (const vp of VIEWPORTS) {
  const page = await browser.newPage();
  await page.setViewport({ width: vp.width, height: vp.height });
  await page.goto(url, { waitUntil: 'networkidle2' });
  await page.waitForSelector('.app', { timeout: 30_000 });
  await new Promise((r) => setTimeout(r, 1500));

  const m = await page.evaluate(() => {
    const tog = document.getElementById('nav-toggle');
    return {
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
      toggleVisible: !!tog && tog.offsetParent !== null,
      topbarOverflows: (() => {
        const t = document.querySelector('.topbar');
        return t ? t.scrollWidth > t.clientWidth + 1 : false;
      })(),
    };
  });

  // The regression that made the console unusable on a phone.
  if (m.scrollWidth > m.innerWidth + 1) {
    failures.push(`${vp.name}: horizontal overflow (${m.scrollWidth} > ${m.innerWidth})`);
  }
  if (m.topbarOverflows) {
    failures.push(`${vp.name}: the top bar overflows its container`);
  }
  const shouldHaveToggle = m.innerWidth <= DRAWER_BREAKPOINT;
  if (shouldHaveToggle && !m.toggleVisible) {
    failures.push(`${vp.name}: no drawer toggle below the breakpoint — navigation is unreachable`);
  }
  if (!shouldHaveToggle && m.toggleVisible) {
    failures.push(`${vp.name}: drawer toggle shown while the sidebar is permanent`);
  }

  await page.screenshot({ path: `screenshots/${vp.name}.png`, fullPage: false });
  console.log(
    `${vp.name} ${m.innerWidth}x${vp.height}: scrollWidth=${m.scrollWidth} toggle=${m.toggleVisible}`,
  );
  await page.close();
}

await browser.close();

for (const f of failures) console.log(`::error::${f}`);
console.log(`viewports: ${VIEWPORTS.length} checked, ${failures.length} failure(s)`);
process.exit(failures.length > 0 ? 1 : 0);
