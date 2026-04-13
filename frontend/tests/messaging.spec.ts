import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';

/**
 * Unique-per-run credentials so repeated test runs never collide on a
 * persistent backend.  The timestamp suffix gives enough uniqueness for
 * local development; in CI each run starts a fresh Testcontainers instance
 * so collisions are impossible anyway.
 */
const RUN_ID = Date.now();
const ALICE = `alice.${RUN_ID}@weaponmail.io`;
const BOB = `bob.${RUN_ID}@weaponmail.io`;
const PASSWORD = 'StrongVaultPass!1'; // ≥ 12 chars – required by the app

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Navigate to /signup, fill the form and wait for the automatic redirect
 * to /inbox that happens after successful key generation.
 *
 * The delay on fill() calls simulates realistic human typing speed and
 * ensures the Angular signal-based form state is fully updated before
 * the form is submitted.
 */
async function signUp(page: Page, username: string, password: string): Promise<void> {
  await page.goto('/signup');
  await expect(page).toHaveURL(/\/signup/);

  await page.fill('#username', username);
  // Small delay between fields to mimic a real user tabbing through the form
  await page.waitForTimeout(300);
  await page.fill('#password', password);
  await page.waitForTimeout(200);
  await page.fill('#confirm', password);
  await page.waitForTimeout(200);

  await page.click('button[type="submit"]');

  // The "generating" spinner is shown while the X25519 keypair + Argon2id
  // KDF completes in the browser.  We wait for it to disappear before
  // asserting the redirect, giving the crypto enough time to finish.
  await expect(page.locator('.generating-state')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.generating-state')).toBeHidden({ timeout: 60_000 });

  // The component sets step = 'done' and schedules a 1500 ms navigate.
  await expect(page).toHaveURL(/\/inbox/, { timeout: 10_000 });
}

/**
 * Navigate to /login and authenticate with an existing account.
 */
async function logIn(page: Page, username: string, password: string): Promise<void> {
  await page.goto('/login');
  await expect(page).toHaveURL(/\/login/);

  await page.fill('input[name="username"]', username);
  await page.waitForTimeout(200);
  await page.fill('input[name="password"]', password);
  await page.waitForTimeout(200);

  await page.click('button[type="submit"]');

  // Wait through the "decrypting" step (Argon2id key re-derivation)
  await expect(page.locator('.generating-state')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.generating-state')).toBeHidden({ timeout: 60_000 });

  await expect(page).toHaveURL(/\/inbox/, { timeout: 10_000 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('E2EE Messaging flow', () => {
  let browser: Browser;
  let aliceCtx: BrowserContext;
  let bobCtx: BrowserContext;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser: b }) => {
    browser = b;

    // Two fully isolated contexts – no shared cookies, localStorage, or
    // session storage.  This mirrors two separate physical users.
    aliceCtx = await browser.newContext();
    bobCtx = await browser.newContext();

    alicePage = await aliceCtx.newPage();
    bobPage = await bobCtx.newPage();
  });

  test.afterAll(async () => {
    await aliceCtx.close();
    await bobCtx.close();
  });

  // -------------------------------------------------------------------------
  // Step 1 – Sign up
  // -------------------------------------------------------------------------

  test('Alice can sign up and land on her inbox', async () => {
    await signUp(alicePage, ALICE, PASSWORD);

    // Inbox header shows the authenticated username
    await expect(alicePage.locator('.inbox-header h2')).toContainText(ALICE, {
      timeout: 10_000,
    });
  });

  test('Bob can sign up and land on his inbox', async () => {
    await signUp(bobPage, BOB, PASSWORD);

    await expect(bobPage.locator('.inbox-header h2')).toContainText(BOB, {
      timeout: 10_000,
    });
  });

  // -------------------------------------------------------------------------
  // Step 2 – Alice sends an encrypted message to Bob
  // -------------------------------------------------------------------------

  test('Alice can compose and send an E2EE message to Bob', async () => {
    // Alice is already on her inbox after signup; navigate to compose
    await alicePage.click('.btn-compose');
    await expect(alicePage).toHaveURL(/\/compose/);

    const subject = `Hello from Alice – ${RUN_ID}`;
    const body = 'This message is end-to-end encrypted. Only Bob can read it.';

    // Realistic typing – delay simulates human key-press cadence (≈ 80 WPM)
    await alicePage.fill('input[name="recipient"]', BOB);
    await alicePage.waitForTimeout(300);
    await alicePage.fill('input[name="subject"]', subject);
    await alicePage.waitForTimeout(200);
    await alicePage.fill('textarea[name="body"]', body);
    await alicePage.waitForTimeout(500);

    // Click send and wait for the button to return to its non-sending label,
    // indicating that the ECDH encryption + HTTP POST have completed.
    await alicePage.click('button[type="submit"]');
    // After sending, the app navigates back to the inbox
    await expect(alicePage).toHaveURL(/\/inbox/, { timeout: 30_000 });
  });

  // -------------------------------------------------------------------------
  // Step 3 – Bob receives the message in real-time via SSE
  // -------------------------------------------------------------------------

  test('Bob receives the message in real-time via SSE without refreshing', async () => {
    // Bob is already authenticated and on his inbox from the signup step.
    // The InboxStreamService has an open EventSource connection.
    // We wait for the new message row to appear without any manual refresh.
    const subject = `Hello from Alice – ${RUN_ID}`;

    // Allow enough time for Kafka event → SSE → Angular signal update
    await expect(
      bobPage.locator('.message-row', { hasText: subject })
    ).toBeVisible({ timeout: 60_000 });
  });

  // -------------------------------------------------------------------------
  // Step 4 – Bob can open and read the decrypted message
  // -------------------------------------------------------------------------

  test('Bob can open the message and see the decrypted body', async () => {
    const subject = `Hello from Alice – ${RUN_ID}`;

    await bobPage.locator('.message-row', { hasText: subject }).click();
    await expect(bobPage).toHaveURL(/\/message\//, { timeout: 10_000 });

    // The detail view decrypts the body in the browser using Bob's X25519
    // private key.  Wait for the body container to show the plaintext.
    await expect(bobPage.locator('.body-text')).toContainText(
      'This message is end-to-end encrypted. Only Bob can read it.',
      { timeout: 30_000 }
    );

    // Confirm the "zero-knowledge" security footer is visible
    await expect(bobPage.locator('.security-footer')).toBeVisible();
  });
});
