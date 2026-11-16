import test from 'node:test';
import assert from 'node:assert/strict';
import { createRelay, sanitizeReport } from '../server.mjs';
const report = (id = 'startup-test12345') => ({
  schema: 1, id, supportCode: 'SESSION-NETWORK', createdAtUtc: '2026-11-13T00:00:00Z',
  app: { version: '1.0', build: '2', platform: 'ios' }, requests: [{
    url: 'https://185-129-48-150.sslip.io/api/v1/auth/guest/', method: 'POST', httpStatus: null,
    originalError: { message: 'Network request failed' },
  }],
});
async function setup(t, fetchImpl) {
  const server = createRelay({ token: 'fake-token-for-tests', chatId: '123', fetchImpl });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/startup-reports`;
  return data => fetch(url, { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify(data) });
}
test('sends one JSON document to fixed chat; duplicate IDs are acknowledged', async t => {
  let count = 0;
  const post = await setup(t, async (url, { body }) => {
    count++;
    assert.equal(url, 'https://api.telegram.org/botfake-token-for-tests/sendDocument');
    assert.equal(body.get('chat_id'), '123');
    const doc = JSON.parse(await body.get('document').text());
    assert.equal(doc.id, 'startup-test12345');
    assert.equal(doc.token, undefined);
    return { ok: true, json: async () => ({ ok: true }) };
  });
  const payload = { ...report(), chat_id: 'attacker', token: 'sensitive' };
  assert.equal((await post(payload)).status, 200);
  assert.equal((await post(payload)).status, 200);
  assert.equal(count, 1);
});
test('Telegram rejection is not reported as successful delivery', async t => {
  const post = await setup(t, async () => ({ ok: true, json: async () => ({ ok:false }) }));
  assert.equal((await post(report())).status, 503);
});
test('invalid/oversized input never reaches Telegram', async t => {
  let count = 0;
  const post = await setup(t, async () => { count++; throw new Error('must not run'); });
  assert.equal((await post({})).status, 400);
  assert.equal((await post({ data:'x'.repeat(100000) })).status, 413);
  assert.equal(count, 0);
});
test('global delivery limit bounds public endpoint spam', async t => {
  let count = 0;
  const post = await setup(t, async () => { count++; return { ok: true, json: async () => ({ok:true}) }; });
  for (let i=0;i<3;i++) assert.equal((await post(report(`startup-count000${i}`))).status,200);
  assert.equal((await post(report('startup-count0004'))).status,429);
  assert.equal(count,3);
});
test('sanitizer omits unknown/private fields, query parameters and credentials', () => {
  const p = report();
  p.password='private';
  p.requests[0].headers={Authorization:'Bearer private'};
  p.requests[0].url += '?token=private';
  p.requests[0].originalError.message='Failed Bearer secret-token for person@example.com token=private';
  p.requests[0].errorBodyPreview={detail:'Denied person@example.com', account:{id:'private'}};
  const out=JSON.stringify(sanitizeReport(p, 'https://185-129-48-150.sslip.io'));
  for(const value of ['private','secret-token','person@example.com','?token']) assert.equal(out.includes(value),false);
});

test('new correlation and read-only connectivity records survive sanitizing', () => {
  const p = report();
  Object.assign(p.requests[0], {
    requestId:'saqtau-test-request-12345',serverRequestId:'1234567890abcdef1234567890abcdef',
    fetchConfiguration:'react-native-requested',networkRevision:'v1.3.11-startup-r1',
    timeoutSource:'client-deadline',
  });
  p.connectivity=[{url:'https://185-129-48-150.sslip.io/api/v1/ready/',method:'GET',httpStatus:503,
    headers:{Authorization:'Bearer secret'}}];
  const clean=sanitizeReport(p,'https://185-129-48-150.sslip.io');
  assert.equal(clean.requests[0].requestId,p.requests[0].requestId);
  assert.equal(clean.requests[0].serverRequestId,p.requests[0].serverRequestId);
  assert.equal(clean.requests[0].timeoutSource,'client-deadline');
  assert.equal(clean.connectivity[0].httpStatus,503);
  assert.equal(JSON.stringify(clean).includes('secret'),false);
});
test('unknown probe URLs and invalid identifiers are discarded', () => {
  const p=report();
  p.requests[0].requestId='Bearer secret';
  p.requests[0].serverRequestId='private@example.com';
  p.connectivity=[{url:'https://other.example/private'},{url:'https://185-129-48-150.sslip.io/api/v1/auth/me/'}];
  const clean=sanitizeReport(p,'https://185-129-48-150.sslip.io');
  assert.equal(clean.requests[0].requestId,null);
  assert.equal(clean.requests[0].serverRequestId,null);
  assert.deepEqual(clean.connectivity,[]);
});
