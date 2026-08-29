import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const sessionUrl = (autoplay: 0 | 1) => `/?autoplay=${autoplay}#/sessions/session-hf-xnode-021`;

test('the full console surrounds the causal replay', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Workload protection' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' })).toBeVisible();
  await page.getByRole('button', { name: 'Sessions' }).click();
  await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible();
  await page.getByRole('button', { name: /Credentialed agent created a workload/ }).click();
  await page.getByRole('button', { name: /Open causal replay/ }).click();
  await expect(page.getByRole('heading', { name: 'Credentialed agent created a workload on another node' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: 'Operations', exact: true })).toBeVisible();
});

test('an observed workload can apply its suggested protection set', async ({ page }) => {
  await page.goto('/');
  const workload = page.locator('.workload-row', { hasText: 'datasets-server' });
  await expect(workload.locator('.workload-mode')).toHaveText('Observe');
  await workload.getByRole('button', { name: /Protect 4 policies/ }).click();
  await expect(workload.locator('.workload-mode')).toHaveText('Observe');
  await expect(workload.getByRole('region', { name: 'Suggested policies' })).toContainText('Block worker environment reads');
  await workload.getByRole('button', { name: 'Apply 4 suggestions to datasets-server' }).click();
  await expect(workload.locator('.workload-mode')).toHaveText('Protected');
  await expect(workload.getByText('Fixture active', { exact: true })).toBeVisible();
  await expect(workload.getByRole('button', { name: 'Current policy' })).toBeVisible();
  await expect(workload.getByText('No new suggestions. Mithril continues to observe for changes.')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('4 suggested policies applied');
});

test('workload policy details expand and edit in place', async ({ page }) => {
  await page.goto('/');
  const workload = page.locator('.workload-row', { hasText: 'datasets-server' });
  await workload.getByRole('button', { name: 'Show policies for datasets-server' }).click();
  const policies = workload.getByRole('region', { name: 'Policies for datasets-server' });
  await expect(policies.getByRole('region', { name: 'Current policies' })).toBeVisible();
  await expect(policies.getByRole('region', { name: 'Suggested policies' })).toContainText('Block worker environment reads');

  const rule = policies.getByTestId('workload-rule-datasets-proc');
  await rule.getByRole('button', { name: 'Edit' }).click();
  await rule.getByLabel('Policy name').fill('Block dataset worker environment reads');
  await rule.getByLabel('Rule').fill('deny file.read /proc/** source=dataset-worker exact=true');
  await rule.getByRole('button', { name: 'Save local edit' }).click();
  await expect(rule).toContainText('Block dataset worker environment reads');
  await expect(rule).toContainText('exact=true');

  await page.getByRole('button', { name: 'Show policies for database-router' }).click();
  await expect(page.getByRole('region', { name: 'Policies for database-router' })).toContainText('Block unmatched database clients');
});

test('the workload policy set supports adding and removing policies', async ({ page }) => {
  await page.goto('/');
  const workload = page.locator('.workload-row', { hasText: 'datasets-server' });
  await workload.getByRole('button', { name: 'Show policies for datasets-server' }).click();
  const policies = workload.getByRole('region', { name: 'Policies for datasets-server' });
  const current = policies.getByRole('region', { name: 'Current policies' });

  await policies.getByRole('button', { name: 'Add policy' }).click();
  const form = policies.locator('.add-policy-form');
  await form.getByLabel('Policy name').fill('Permit signed cache reads');
  await form.getByLabel('Action').selectOption('Allow list');
  await form.getByLabel('Rule').fill('allow file.read datasets/cache/** identity=dataset-worker');
  await form.getByRole('button', { name: 'Add to current policies' }).click();
  const added = current.locator('.workload-rule', { hasText: 'Permit signed cache reads' });
  await expect(added).toContainText('Operator-authored local policy');

  await added.getByRole('button', { name: 'Remove' }).click();
  await expect(added).toContainText('Remove Permit signed cache reads?');
  await added.getByRole('button', { name: 'Remove policy' }).click();
  await expect(current.getByText('Permit signed cache reads')).toHaveCount(0);

  const suggestion = policies.getByTestId('workload-rule-datasets-proc');
  await suggestion.getByRole('button', { name: 'Remove' }).click();
  await suggestion.getByRole('button', { name: 'Remove policy' }).click();
  await expect(workload.getByRole('button', { name: /Protect 3 policies/ })).toBeVisible();
});

test('the surrounding product workspaces remain interactive', async ({ page }) => {
  await page.goto('/');
  for (const workspace of [
    ['Findings', 'Findings'],
    ['Policies', 'Policy rollout'],
    ['Evidence', 'Evidence'],
    ['Response', 'Response'],
    ['Agent', 'Agent mode'],
    ['Release', 'Release claim'],
  ] as const) {
    await page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: new RegExp(`^${workspace[0]}`) }).click();
    await expect(page.getByRole('heading', { name: workspace[1], exact: true })).toBeVisible();
  }
});

test('the top command field routes by an explicit workspace name', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('searchbox', { name: 'Go to a console workspace' }).fill('evidence');
  await page.getByRole('searchbox', { name: 'Go to a console workspace' }).press('Enter');
  await expect(page.getByRole('heading', { name: 'Evidence', exact: true })).toBeVisible();
});

test('a selected policy can be edited and saved as a local draft', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Console sections' }).getByRole('button', { name: 'Policies' }).click();
  await page.getByRole('button', { name: /delivery model-delivery/ }).click();
  await expect(page.getByRole('heading', { name: 'delivery / model-delivery' })).toBeVisible();
  await page.getByRole('button', { name: 'Edit policy' }).click();
  await page.getByLabel('Workload selector').fill('app=model-publisher,track=stable');
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByLabel('Workload selector')).toHaveValue('app=model-publisher,track=stable');
  await expect(page.getByRole('status')).toContainText('Policy draft saved locally');
});

test('Observe mode exposes evidence-backed suggestions that apply to the draft', async ({ page }) => {
  await page.goto('/#/policies');
  await page.getByRole('button', { name: /research research-observe/ }).click();
  await expect(page.getByRole('heading', { name: 'Policy suggestions' })).toBeVisible();
  await page.getByRole('button', { name: 'Apply suggestion' }).first().click();
  await expect(page.getByLabel('Rules')).toHaveValue(/allow file\.read datasets\/cache\/\*\*/);
  await expect(page.getByRole('button', { name: 'Applied to draft' })).toBeDisabled();
  await expect(page.getByRole('status')).toContainText('Suggestion applied to the local research-observe draft');
});

test('Agent mode explains system state and routes to supporting evidence', async ({ page }) => {
  await page.goto('/#/agent');
  await expect(page.getByRole('heading', { name: 'Agent mode' })).toBeVisible();
  await page.getByRole('button', { name: 'Why is the release blocked?' }).click();
  await expect(page.getByText(/active fixture equality is 131 of 133/)).toBeVisible();
  await page.getByRole('button', { name: 'Review release blockers' }).click();
  await expect(page.getByRole('heading', { name: 'Release claim' })).toBeVisible();
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

test('the graph marks the stop and keeps counterfactual review outside evidence', async ({ page }) => {
  await page.goto(sessionUrl(0));
  const stop = page.getByTestId('operation-secret-open');
  await expect(stop.getByText('STOPPED HERE')).toBeVisible();
  const recordedEdgeCount = await page.locator('.edge-inspect').count();

  await page.getByRole('button', { name: 'Show if allowed' }).click();
  const counterfactual = page.getByTestId('counterfactual-path');
  await expect(counterfactual).toContainText('COUNTERFACTUAL · INCIDENT-GROUNDED · NOT EVIDENCE');
  await expect(counterfactual).toContainText('Privileged host Pod');
  await expect(counterfactual).toBeInViewport();
  await expect(page.locator('.edge-inspect')).toHaveCount(recordedEdgeCount);

  await page.getByRole('button', { name: 'Review incorrect stop' }).click();
  const review = page.getByRole('dialog', { name: 'Review this denied access' });
  await expect(review).toContainText('The access stays denied.');
  await review.getByText('Show evidence identifiers').click();
  await expect(review).toContainText('DENIED_BEFORE_EFFECT');
  await review.getByLabel('What should this workload have been allowed to do?').fill('The admitted repair job needs one read of this exact object.');
  await review.getByRole('button', { name: 'Submit exception for approval' }).click();
  await expect(review.getByRole('status')).toContainText('graph revision remains unchanged');
  await expect(stop).toHaveClass(/outcome-denied/);
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
  expect(await detail.evaluate((element) => getComputedStyle(element).right)).toBe('18px');
  await page.locator('.graph-viewport').evaluate((element) => { element.scrollLeft += 400; });
  expect(await detail.evaluate((element) => getComputedStyle(element).right)).toBe('18px');
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
  await page.getByRole('button', { name: 'All events' }).click();
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

test('mobile graph navigation reaches the stopped effect and the outline fits', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(sessionUrl(0));
  await page.getByRole('button', { name: 'Stopped effect' }).click();
  await expect.poll(() => page.getByTestId('operation-secret-open').evaluate((element) => {
    const operation = element.getBoundingClientRect();
    const viewport = element.closest('.graph-viewport')!.getBoundingClientRect();
    return operation.left >= viewport.left && operation.right <= viewport.right
      && operation.top >= viewport.top && operation.bottom <= viewport.bottom;
  })).toBe(true);
  await page.getByRole('button', { name: 'Ledger' }).click();
  expect(await page.locator('.ledger').evaluate((element) => element.scrollWidth - element.clientWidth)).toBe(0);
});

test('mobile incorrect-stop review keeps the decision controls in view', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(sessionUrl(13));
  await page.getByRole('button', { name: 'Review incorrect stop' }).click();
  const review = page.getByRole('dialog', { name: 'Review this denied access' });
  await expect(review).toBeVisible();
  await expect(review.getByLabel('What should this workload have been allowed to do?')).toBeInViewport();
  await expect(review.getByRole('button', { name: 'Submit exception for approval' })).toBeInViewport();
  expect(await review.evaluate((element) => element.scrollWidth - element.clientWidth)).toBe(0);
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

test('mobile keeps the protection and response decisions inside the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/');
  const workload = page.locator('.workload-row', { hasText: 'datasets-server' });
  await expect(workload.getByRole('button', { name: /Protect 4 policies/ })).toBeInViewport();
  await workload.getByRole('button', { name: 'Show policies for datasets-server' }).click();
  await expect(workload.getByRole('region', { name: 'Suggested policies' })).toBeVisible();
  expect(await workload.evaluate((element) => element.scrollWidth - element.clientWidth)).toBe(0);

  await page.goto('/#/response');
  const responseTarget = page.locator('.blast-radius').getByText('4 active Pods', { exact: true });
  await responseTarget.scrollIntoViewIfNeeded();
  await expect(responseTarget).toBeInViewport();
  expect(await page.locator('.response-workbench').evaluate((element) => element.scrollWidth - element.clientWidth)).toBe(0);
});

test('every console workspace has no serious or critical accessibility violations', async ({ page }) => {
  test.setTimeout(60_000);
  const violations: string[] = [];
  for (const [workspace, url] of [
    ['operations', '/'],
    ['sessions', '/#/sessions'],
    ['findings', '/#/findings'],
    ['policies', '/#/policies'],
    ['evidence', '/#/evidence'],
    ['response', '/#/response'],
    ['agent', '/#/agent'],
    ['release', '/#/release'],
    ['session map', sessionUrl(0)],
  ] as const) {
    await page.goto(url);
    const audit = await new AxeBuilder({ page }).disableRules(['scrollable-region-focusable']).analyze();
    violations.push(...audit.violations
      .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
      .flatMap((violation) => violation.nodes.map((node) => `${workspace}: ${violation.id} ${node.target.join(' ')}`)));
  }
  await page.getByRole('button', { name: 'Ledger' }).click();
  const ledger = await new AxeBuilder({ page }).analyze();
  violations.push(...ledger.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .flatMap((violation) => violation.nodes.map((node) => `session ledger: ${violation.id} ${node.target.join(' ')}`)));
  expect(violations).toEqual([]);
});
