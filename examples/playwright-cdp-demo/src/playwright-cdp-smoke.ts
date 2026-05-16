import { chromium, type Browser, type BrowserContext, type CDPSession, type Page } from 'playwright';

const endpoint = process.env.EREBOR_CDP_ENDPOINT ?? 'ws://127.0.0.1:3738/';

assertGovernedEndpoint(endpoint);

const browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });

try {
  const context = firstContext(browser);
  const page = await firstPage(context);

  await page.goto('data:text/html,<title>Erebor</title><h1 id="status">governed</h1>');
  const status = await page.locator('#status').textContent();
  if (status !== 'governed') {
    throw new Error(`Expected governed page text, got ${JSON.stringify(status)}.`);
  }

  const cdpSession = await context.newCDPSession(page);
  try {
    await assertSuspiciousScriptDenied(page, cdpSession);
  } finally {
    await cdpSession.detach();
  }

  console.log('Playwright CDP smoke passed through Erebor.');
} finally {
  await browser.close();
}

function assertGovernedEndpoint(value: string): void {
  const url = new URL(value);
  if (url.protocol !== 'ws:') {
    throw new Error('The smoke demo expects a local ws:// governed endpoint.');
  }
  if (url.pathname.startsWith('/devtools/browser/') || url.pathname.startsWith('/devtools/page/')) {
    throw new Error('Refusing raw Chrome DevTools endpoint; use Erebor public endpoint.');
  }

  if (value.includes('...')) {
    throw new Error('Replace the README placeholder with the exact governed CDP endpoint logged by Erebor.');
  }
}

function firstContext(browser: Browser): BrowserContext {
  const context = browser.contexts()[0];
  if (!context) {
    throw new Error('Playwright did not expose a browser context over the governed CDP endpoint.');
  }

  return context;
}

async function firstPage(context: BrowserContext): Promise<Page> {
  return context.pages()[0] ?? context.newPage();
}

async function assertSuspiciousScriptDenied(page: Page, cdpSession: CDPSession): Promise<void> {
  let sawPolicyError = false;
  try {
    await cdpSession.send('Runtime.evaluate', {
      expression: "window.__ereborSmokeValue = 'owned-denied'; window.__ereborSmokeValue",
      returnByValue: true,
    });
  } catch (error) {
    const message = String(error);
    console.log('Received error from suspicious script payload:', message);
    if (!message.includes('playwright smoke denied suspicious script payload')) {
      throw new Error(`Expected Erebor policy denial, got ${message}.`);
    }
    sawPolicyError = true;
  }

  const browserState = await page.evaluate(() => globalThis.window.__ereborSmokeValue ?? null);
  if (browserState !== null) {
    throw new Error(`Denied script mutated browser state: ${JSON.stringify(browserState)}.`);
  }

  if (!sawPolicyError) {
    throw new Error('Expected suspicious script payload to receive an Erebor policy error.');
  }
}

declare global {
  interface Window {
    __ereborSmokeValue?: string;
  }
}
