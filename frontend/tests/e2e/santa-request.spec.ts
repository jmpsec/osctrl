import { expect, test } from '@playwright/test';
import { ENV, FakeApi, openPage } from './fake-api';

const SHA = 'ab'.repeat(32);
const MACHINE = '0A1B2C3D-1111-2222-3333-444455556666';

// A blocked user asks for the file from the link in the Santa dialog, an
// environment admin approves it in the Requests tab, and the allow rule shows
// in the Rules tab.
test('request, approve, rule', async ({ context }) => {
  const api = new FakeApi();
  await api.install(context);

  api.as('dave');
  const requester = await openPage(context);
  await requester.goto(`/santa/request/${ENV}?sha256=${SHA}&machine_id=${MACHINE}`);
  await expect(requester.getByRole('heading', { name: 'Request approval' })).toBeVisible();
  await expect(requester.getByText(SHA)).toBeVisible();
  const send = requester.getByRole('button', { name: 'Send request' });
  // The file request comes first; the MONITOR request form follows it.
  const form = requester.locator('form').first();
  await expect(send).toBeDisabled();
  await form.getByLabel('Why do you need it?').fill('Build tool for the release');
  await send.click();
  await expect(form.getByRole('status')).toContainText('Your request was sent.');
  await expect(form.getByRole('status')).toContainText('Pending');
  expect(api.requests).toMatchObject([{ file_sha256: SHA, machine_id: MACHINE, requester: 'dave', status: 'pending' }]);

  api.as('admin');
  const admin = await openPage(context);
  await admin.goto(`/_app/env/${ENV}/santa?tab=requests`);
  await expect(admin.getByRole('tab', { name: 'Requests' })).toHaveAttribute('aria-selected', 'true');
  await expect(admin.getByText('Build tool for the release')).toBeVisible();
  await admin.getByRole('button', { name: 'Approve Tool.app' }).click();
  const dialog = admin.getByRole('dialog');
  await expect(dialog.getByLabel('Scope')).toHaveValue('node');
  await dialog.getByRole('button', { name: 'Approve' }).click();
  await expect(dialog).toBeHidden();
  expect(api.decisions).toMatchObject([{ decision: 'approve', scope: 'node' }]);
  expect(api.requests[0]).toMatchObject({ status: 'approved', decided_by: 'admin', rule_id: 1 });

  await admin.getByRole('tab', { name: 'Rules' }).click();
  await expect(admin).toHaveURL(/tab=rules/);
  const row = admin.getByRole('row').filter({ hasText: SHA });
  await expect(row).toContainText('BINARY');
  await expect(row).toContainText('ALLOWLIST');
  await expect(row).toContainText(MACHINE);

  // The requester sees the decision on their page.
  api.as('dave');
  await requester.reload();
  await expect(requester.getByRole('cell', { name: 'Approved' })).toBeVisible();

  expect(api.unknown).toEqual([]);
});

// The approve link of a notification lands on a confirmation page: opening it
// decides nothing, confirming does, and the link works once.
test('approve from a notification link', async ({ context }) => {
  const api = new FakeApi();
  await api.install(context);
  api.requests.push({
    id: 7, file_sha256: SHA, machine_id: MACHINE, justification: 'Build tool for the release', requester: 'dave',
    status: 'pending', reason: '', decided_by: '', rule_id: 0, created_at: new Date().toISOString(),
  });
  api.links.set('LINK-TOKEN', 7);

  const page = await openPage(context);
  await page.goto(`/santa/decide/${ENV}?request=7&action=approve#LINK-TOKEN`);
  await expect(page.getByRole('heading', { name: 'Approve request' })).toBeVisible();
  await expect(page.getByText('Build tool for the release')).toBeVisible();
  expect(api.requests[0].status, 'opening the link decides nothing').toBe('pending');
  await page.getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByRole('status')).toContainText('Approved');
  expect(api.requests[0]).toMatchObject({ status: 'approved', decided_by: 'admin', rule_id: 1 });
  expect(api.links.size, 'the link works once').toBe(0);

  await page.getByRole('link', { name: 'Open the Requests tab' }).click();
  await expect(page).toHaveURL((url) => url.pathname === `/_app/env/${ENV}/santa` && url.search === '?tab=requests');
  await expect(page.getByRole('tab', { name: 'Requests' })).toHaveAttribute('aria-selected', 'true');

  expect(api.unknown).toEqual([]);
});
