import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';

const endpoint = process.env.EREBOR_CDP_ENDPOINT ?? 'ws://127.0.0.1:3740/';
const googleHomeUrl = 'https://www.google.com/';
const microsoftUrl = 'https://www.microsoft.com/';
const allowedSearchTerm = 'Something Something';
const deniedSearchTerm = 'Something Else';
const navigationOptions = { waitUntil: 'commit' as const, timeout: 30_000 };

assertGovernedEndpoint(endpoint);

const browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });

try {
  const context = firstContext(browser);
  const page = await firstPage(context);

  await page.goto(googleHomeUrl, navigationOptions);
  await page.goto(googleSearchUrl(allowedSearchTerm), navigationOptions);

  await assertNavigationDenied(
    page,
    microsoftUrl,
    'navigation to microsoft.com is denied by demo policy',
  );
  await assertNavigationDenied(
    page,
    googleSearchUrl(deniedSearchTerm),
    'only the Something Something Google search is allowed by demo policy',
  );

  console.log('Playwright Google policy smoke passed through Erebor.');
} finally {
  await browser.close();
}

function googleSearchUrl(query: string): string {
  const params = new URLSearchParams({ q: query });
  return `https://www.google.com/search?${params.toString()}`;
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

async function assertNavigationDenied(
  page: Page,
  url: string,
  expectedPolicyReason: string,
): Promise<void> {
  const beforeUrl = page.url();
  let sawPolicyError = false;

  try {
    await page.goto(url, navigationOptions);
  } catch (error) {
    const message = String(error);
    console.log(`Received navigation policy error for ${url}:`, message);
    if (!message.includes(expectedPolicyReason)) {
      throw new Error(`Expected Erebor policy denial, got ${message}.`);
    }
    sawPolicyError = true;
  }

  const afterUrl = page.url();
  if (afterUrl !== beforeUrl) {
    throw new Error(`Denied navigation mutated browser state from ${beforeUrl} to ${afterUrl}.`);
  }

  if (!sawPolicyError) {
    throw new Error(`Expected navigation to ${url} to receive an Erebor policy error.`);
  }
}
