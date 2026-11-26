import { test, expect } from './fixtures/dashboard';

/**
 * Functional E2E test suite for the WHOIS Checkup tool (/whois).
 *
 * Covers:
 * 1. Initial page load and empty state UI
 * 2. Live RDAP lookup, stat cards, status labels, and sections
 * 3. Raw RDAP view toggle (expand / collapse)
 * 4. Input normalization (URLs, schemes, paths)
 * 5. Input validation error handling (invalid domain names)
 * 6. URL query param prefill and auto-lookup (?domain=...)
 * 7. Cross-tool navigation links (DNS, SSL)
 * 8. Share modal creation and shared snapshot view (/s/[code])
 * 9. Unregistered / non-existent domain handling
 */

const EXTERNAL_NOISE = [
  /ERR_NAME_NOT_RESOLVED/i,
  /ERR_INTERNET_DISCONNECTED/i,
  /Failed to load resource: the server responded with a status of 401/i,
  /Failed to load resource: the server responded with a status of 403/i,
];

function realErrors(watcher: { errors: string[] }): string[] {
  return watcher.errors.filter((e) => !EXTERNAL_NOISE.some((re) => re.test(e)));
}

test.describe('WHOIS Checkup Tool (/whois)', () => {
  test('1. Initial page load renders hero, input, and empty state without JS errors', async ({
    page,
    console: watcher,
  }) => {
    const response = await page.goto('/whois', { waitUntil: 'domcontentloaded' });
    expect(response?.status()).toBe(200);

    // Hero title & description
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('WHOIS Lookup');
    await expect(page.getByText('Inspect domain registration details')).toBeVisible();

    // Input card and controls
    const input = page.getByPlaceholder('e.g. openai.com');
    await expect(input).toBeVisible();
    await expect(page.getByRole('button', { name: /Lookup/i })).toBeVisible();

    // Empty state
    await expect(page.getByText('Explore a domain’s registration')).toBeVisible();
    await expect(
      page.getByText('Enter a domain to inspect its registrar, registration timeline, status, and nameservers.')
    ).toBeVisible();

    expect(realErrors(watcher), 'console errors on initial load').toEqual([]);
  });

  test('2. Live lookup displays domain stats, status labels, and details', async ({
    page,
    console: watcher,
  }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });

    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('google.com');
    await page.getByRole('button', { name: /Lookup/i }).click();

    // Wait for the snapshot cards to appear
    const statCards = page.locator('.stat-card');
    await expect(statCards.first()).toBeVisible({ timeout: 15_000 });
    await expect(statCards).toHaveCount(5);

    // Verify stat card contents
    await expect(statCards.nth(0)).toContainText('google.com');
    await expect(statCards.nth(0)).toContainText('Domain');
    await expect(statCards.nth(1)).toContainText('Registered');
    await expect(statCards.nth(1)).toContainText('Registration');
    await expect(statCards.nth(2)).toContainText('MarkMonitor Inc.');
    await expect(statCards.nth(2)).toContainText('Registrar');
    await expect(statCards.nth(3)).toContainText('Days Until Expiry');
    await expect(statCards.nth(4)).toContainText('DNSSEC');

    // Source indicator
    await expect(page.getByText('Source: RDAP')).toBeVisible();

    // Key sections
    await expect(page.getByRole('heading', { name: 'Domain Status' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Registrar & Dates' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Nameserver Comparison' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Risk Signals' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Raw RDAP' })).toBeVisible();

    expect(realErrors(watcher), 'console errors during live lookup').toEqual([]);
  });

  test('3. Raw RDAP view can be expanded and collapsed', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });
    await page.getByPlaceholder('e.g. openai.com').fill('google.com');
    await page.getByRole('button', { name: /Lookup/i }).click();

    await expect(page.getByRole('heading', { name: 'Raw RDAP' })).toBeVisible({ timeout: 15_000 });

    const toggleBtn = page.getByRole('button', { name: /Show Raw RDAP/i });
    await expect(toggleBtn).toBeVisible();

    // Expand
    await toggleBtn.click();
    const rawPre = page.locator('pre');
    await expect(rawPre).toBeVisible();
    await expect(rawPre).toContainText('GOOGLE.COM');
    await expect(page.getByRole('button', { name: /Hide Raw RDAP/i })).toBeVisible();

    // Collapse
    await page.getByRole('button', { name: /Hide Raw RDAP/i }).click();
    await expect(rawPre).toBeHidden();
  });

  test('4. Input normalization strips URL schemes and trailing paths', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });

    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('https://google.com/intl/en/about');
    await page.getByRole('button', { name: /Lookup/i }).click();

    // Normalized value in input
    await expect(input).toHaveValue('google.com');

    // Stat card shows normalized domain
    const domainStat = page.locator('.stat-card').first();
    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    await expect(domainStat).toContainText('google.com');
  });

  test('5. Invalid domain name shows error alert gracefully', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });

    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('invalid..domain');
    await page.getByRole('button', { name: /Lookup/i }).click();

    const alert = page.locator('.alert-custom');
    await expect(alert).toBeVisible({ timeout: 10_000 });
    await expect(alert).toContainText('Invalid domain name.');
  });

  test('6. URL query param prefill triggers auto-lookup on navigation', async ({ page }) => {
    await page.goto('/whois?domain=google.com', { waitUntil: 'domcontentloaded' });

    // Input populated
    const input = page.getByPlaceholder('e.g. openai.com');
    await expect(input).toHaveValue('google.com');

    // Results automatically loaded without manual click
    const domainStat = page.locator('.stat-card').first();
    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    await expect(domainStat).toContainText('google.com');
  });

  test('7. Cross-tool links provide seamless navigation to DNS and SSL checkers', async ({ page }) => {
    await page.goto('/whois?domain=google.com', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('.stat-card').first()).toBeVisible({ timeout: 15_000 });

    const dnsLink = page.getByRole('link', { name: /Open DNS Lookup/i });
    await expect(dnsLink).toBeVisible();
    await expect(dnsLink).toHaveAttribute('href', '/dns?domain=google.com&types=NS');

    const sslLink = page.getByRole('link', { name: /Open SSL Checker/i });
    await expect(sslLink).toBeVisible();
    await expect(sslLink).toHaveAttribute('href', '/ssl?domain=google.com');
  });

  test('8. Share snapshot workflow creates shareable link and renders shared view', async ({ page }) => {
    await page.goto('/whois?domain=google.com', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('.stat-card').first()).toBeVisible({ timeout: 15_000 });

    // Open share modal
    await page.getByRole('button', { name: /Share Snapshot/i }).click();
    await expect(page.getByRole('heading', { name: 'Share WHOIS Snapshot' })).toBeVisible();

    // Create share link (without password)
    const createBtn = page.getByRole('button', { name: /Generate Share Link/i });
    await expect(createBtn).toBeVisible();
    await createBtn.click();

    // Confirm share link generated
    await expect(page.getByText('Share link created!')).toBeVisible({ timeout: 10_000 });
    const shareInput = page.locator('span:has-text("/s/")');
    await expect(shareInput).toBeVisible();
    const shareUrl = await shareInput.innerText();
    expect(shareUrl).toContain('/s/');

    // Extract path and navigate to shared view
    const urlObj = new URL(shareUrl);
    await page.goto(urlObj.pathname, { waitUntil: 'domcontentloaded' });

    // Verify shared view banner
    await expect(page.getByText('You are viewing')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('read-only registration data')).toBeVisible();
    await expect(page.getByRole('link', { name: /Open Live Lookup/i })).toBeVisible();

    // Verify snapshot content in shared view
    const sharedStat = page.locator('.stat-card').first();
    await expect(sharedStat).toBeVisible();
    await expect(sharedStat).toContainText('google.com');
  });

  test('9. Unregistered domain fallback identifies not found status', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });

    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('thisdomainclearlydoesnotexist123456789.com');
    await page.getByRole('button', { name: /Lookup/i }).click();

    const statCards = page.locator('.stat-card');
    await expect(statCards.first()).toBeVisible({ timeout: 20_000 });

    // Registration card should report unknown / not found
    await expect(statCards.nth(1)).toContainText('Unknown / Not Found');
    // Source should fallback to WHOIS
    await expect(page.getByText('Source: WHOIS')).toBeVisible();
  });

  test('10. Lookup triggers on Enter key press in input field', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });
    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('cloudflare.com');
    await input.press('Enter');

    const domainStat = page.locator('.stat-card').first();
    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    await expect(domainStat).toContainText('cloudflare.com');
  });

  test('11. Action buttons (Copy, Download HTML, JSON, CSV) execute without crashing', async ({
    page,
    context,
    console: watcher,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/whois?domain=google.com', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('.stat-card').first()).toBeVisible({ timeout: 15_000 });

    // Test Copy Summary
    const copyBtn = page.getByRole('button', { name: /Copy Summary/i });
    await expect(copyBtn).toBeVisible();
    await copyBtn.click();
    await expect(page.getByRole('button', { name: /Copied!/i })).toBeVisible();

    // Test JSON download event
    const jsonDownloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'JSON' }).click();
    const jsonDownload = await jsonDownloadPromise;
    expect(jsonDownload.suggestedFilename()).toBe('google.com-whois-snapshot.json');

    // Test CSV download event
    const csvDownloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'CSV' }).click();
    const csvDownload = await csvDownloadPromise;
    expect(csvDownload.suggestedFilename()).toContain('google.com-whois-snapshot.csv');

    // Test HTML download event
    const htmlDownloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /Download HTML/i }).click();
    const htmlDownload = await htmlDownloadPromise;
    expect(htmlDownload.suggestedFilename()).toBe('google.com-whois-snapshot.html');

    expect(realErrors(watcher), 'console errors during export actions').toEqual([]);
  });

  test('12. Password-protected share creates gated share and unlocks with correct password', async ({
    page,
  }) => {
    await page.goto('/whois?domain=google.com', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('.stat-card').first()).toBeVisible({ timeout: 15_000 });

    // Open share modal
    await page.getByRole('button', { name: /Share Snapshot/i }).click();
    await expect(page.getByRole('heading', { name: 'Share WHOIS Snapshot' })).toBeVisible();

    // Fill password
    const pwdInput = page.getByPlaceholder('Leave blank for public link');
    await pwdInput.fill('secret123');
    await page.getByRole('button', { name: /Generate Share Link/i }).click();

    await expect(page.getByText('Share link created!')).toBeVisible({ timeout: 10_000 });
    const shareInput = page.locator('span:has-text("/s/")');
    const shareUrl = await shareInput.innerText();
    const urlObj = new URL(shareUrl);

    // Navigate to protected share
    await page.goto(urlObj.pathname, { waitUntil: 'domcontentloaded' });

    // Expect password gate
    await expect(page.getByText('Password Protected')).toBeVisible({ timeout: 15_000 });
    const unlockInput = page.getByPlaceholder('Enter password');
    await expect(unlockInput).toBeVisible();

    // Try wrong password
    await unlockInput.fill('wrongpass');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByText(/Incorrect password/i)).toBeVisible({ timeout: 10_000 });

    // Enter correct password
    await unlockInput.fill('secret123');
    await page.getByRole('button', { name: 'Unlock' }).click();

    // Snapshot un-gated and rendered
    await expect(page.getByText('You are viewing')).toBeVisible({ timeout: 15_000 });
    const sharedStat = page.locator('.stat-card').first();
    await expect(sharedStat).toBeVisible();
    await expect(sharedStat).toContainText('google.com');
  });

  test('13. Non-RDAP ccTLD routes through port 43 WHOIS and UI reflects WHOIS source', async ({ page }) => {
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });
    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('denic.de');
    await page.getByRole('button', { name: /Lookup/i }).click();

    const domainStat = page.locator('.stat-card').first();
    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    await expect(domainStat).toContainText('denic.de');

    // UI clearly indicates WHOIS data source and raw WHOIS section
    await expect(page.getByText('Source: WHOIS')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Raw WHOIS' })).toBeVisible();

    const toggleBtn = page.getByRole('button', { name: /Show Raw WHOIS/i });
    await expect(toggleBtn).toBeVisible();
    await toggleBtn.click();
    await expect(page.locator('pre')).toContainText('denic.de');
  });

  test('14. Internationalized Domain Names (Unicode & Punycode) succeed in UI', async ({ page }) => {
    // Test raw Unicode IDN
    await page.goto('/whois', { waitUntil: 'domcontentloaded' });
    const input = page.getByPlaceholder('e.g. openai.com');
    await input.fill('münchen.de');
    await page.getByRole('button', { name: /Lookup/i }).click();

    const domainStat = page.locator('.stat-card').first();
    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    // Domain stat reflects punycode ASCII domain
    await expect(domainStat).toContainText('xn--mnchen-3ya.de');
    await expect(page.getByText('Source: WHOIS')).toBeVisible();

    // Test Punycode directly
    await input.fill('xn--e1afmkfd.xn--p1ai');
    await page.getByRole('button', { name: /Lookup/i }).click();

    await expect(domainStat).toBeVisible({ timeout: 15_000 });
    await expect(domainStat).toContainText('xn--e1afmkfd.xn--p1ai');
    const registrarStat = page.locator('.stat-card').nth(2);
    await expect(registrarStat).toContainText('CC-RF');
  });
});
