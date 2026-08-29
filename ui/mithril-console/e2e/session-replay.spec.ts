import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const sessionUrl = (autoplay: 0 | 1) => `/?autoplay=${autoplay}#/sessions/session-hf-xnode-021`;

test('the full console surrounds the causal replay', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Operations' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' })).toBeVisible();
  await page.getByRole('button', { name: 'Sessions' }).click();
  await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible();
  await page.getByRole('button', { name: /Credentialed agent created a workload/ }).click();
  await page.getByRole('button', { name: /Open causal replay/ }).click();
  await expect(page.getByRole('heading', { name: 'Credentialed agent created a workload on another node' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: 'Operations', exact: true })).toBeVisible();
});

test('the surrounding product workspaces remain interactive', async ({ page }) => {
  await page.goto('/');
  for (const workspace of [
    ['Findings', 'Findings'],
    ['Policies', 'Policy rollout'],
    ['Evidence', 'Evidence'],
    ['Response', 'Response'],
    ['Release', 'Release claim'],
  ] as const) {
    await page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: new RegExp(`^${workspace[0]}`) }).click();
    await expect(page.getByRole('heading', { name: workspace[1], exact: true })).toBeVisible();
  }
});

test('replays the causal front instead of showing the complete graph at once', async ({ page }) => {
  await page.goto(sessionUrl(1));
  await expect(page.getByTestId('operation-session-open')).toBeVisible();
  await expect(page.getByTestId('operation-secret-open')).toHaveCount(0);
  await page.getByLabel('Playback speed').selectOption('2');
  await expect(page.getByTestId('operation-secret-open')).toBeVisible({ timeout: 8_000 });
  expect(Number(await page.getByLabel('Replay position').inputValue())).toBeGreaterThanOrEqual(10);
});

test('clicking an operation expands its evidence inside the graph', async ({ page }) => {
  await page.goto(sessionUrl(0));
  const operation = page.getByTestId('operation-secret-open');
  await operation.getByRole('button').click();
  await expect(operation).toHaveClass(/expanded/);
  await expect(operation.getByText('The exact open was rejected before an fd or secret bytes existed.')).toBeVisible();
  await expect(operation.getByText('obs-wb-4421')).toBeVisible();
  await expect.poll(async () => (await operation.boundingBox())!.width).toBeGreaterThan(300);
  await operation.getByRole('button').click();
  await expect(operation).not.toHaveClass(/expanded/);
});

test('clicking an edge exposes its exact join without replacing the graph', async ({ page }) => {
  await page.goto(sessionUrl(0));
  const edge = page.getByRole('button', { name: /exact task \+ object, direct causal edge/ });
  await edge.scrollIntoViewIfNeeded();
  await edge.click();
  const detail = page.getByTestId('edge-detail');
  await expect(detail).toBeVisible();
  await expect(detail.getByText('task b812')).toBeVisible();
  await expect(detail.getByText('object cloud-token')).toBeVisible();
  await expect(page.getByTestId('operation-secret-open')).toBeVisible();
});

test('the contextual cross-node join stays visibly weaker', async ({ page }) => {
  await page.goto(sessionUrl(0));
  const edge = page.getByRole('button', { name: /shared principal, contextual causal edge/ });
  await edge.scrollIntoViewIfNeeded();
  await edge.click();
  await expect(page.getByTestId('edge-detail')).toHaveClass(/strength-contextual/);
  await expect(page.getByTestId('edge-detail').getByText('ServiceAccount payments-api')).toBeVisible();
});

test('scrubbing and node focus preserve one synchronized investigation state', async ({ page }) => {
  await page.goto(sessionUrl(0));
  await page.getByLabel('Replay position').fill('3');
  await expect(page.getByTestId('operation-api-send')).toBeVisible();
  await expect(page.getByTestId('operation-api-request')).toHaveCount(0);

  await page.getByRole('button', { name: 'worker-a', exact: true }).first().click();
  await expect(page.getByTestId('operation-api-send')).not.toHaveClass(/dimmed/);
  await page.getByRole('button', { name: 'Reveal all' }).click();
  await expect(page.getByTestId('operation-secret-open')).toBeVisible();
});

test('map and ledger use the same operation selection', async ({ page }) => {
  await page.goto(sessionUrl(0));
  await page.getByTestId('operation-finding').getByRole('button').click();
  await page.getByRole('button', { name: 'Ledger' }).click();
  const row = page.locator('.ledger-row.expanded');
  await expect(row.getByText('Cross-node finding confirmed')).toBeVisible();
  await expect(row.getByText('GraphAndFindingOwner')).toBeVisible();
});

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 375, height: 812 },
]) {
  test(`${viewport.name} keeps page overflow inside the graph viewport`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(sessionUrl(0));
    await page.getByTestId('operation-secret-open').getByRole('button').click();
    const overflow = await page.evaluate(() => ({
      body: document.body.scrollWidth - document.body.clientWidth,
      root: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      graph: document.querySelector('.graph-viewport')!.scrollWidth > document.querySelector('.graph-viewport')!.clientWidth,
    }));
    expect(overflow.body).toBe(0);
    expect(overflow.root).toBe(0);
    expect(overflow.graph).toBe(true);
    await page.screenshot({ path: `test-results/${viewport.name}.png`, fullPage: true });
  });
}

test('map and ledger have no critical accessibility violations', async ({ page }) => {
  await page.goto('/');
  const operations = await new AxeBuilder({ page }).analyze();
  expect(operations.violations.filter((violation) => violation.impact === 'critical')).toEqual([]);
  await page.goto(sessionUrl(0));
  const map = await new AxeBuilder({ page }).disableRules(['scrollable-region-focusable']).analyze();
  expect(map.violations.filter((violation) => violation.impact === 'critical')).toEqual([]);
  await page.getByRole('button', { name: 'Ledger' }).click();
  const ledger = await new AxeBuilder({ page }).analyze();
  expect(ledger.violations.filter((violation) => violation.impact === 'critical')).toEqual([]);
});
