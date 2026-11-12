import http from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 96 * 1024;
function clean(value, max = 1200) {
  if (value == null) return null;
  return String(value)
    .replace(/https?:\/\/[^\s"'<>]+/gi, raw => {
      try { const u = new URL(raw); return `${u.origin}${u.pathname}`; }
      catch { return '[url omitted]'; }
    })
    .replace(/\bBearer\s+[^\s"',;]+/gi, 'Bearer [redacted]')
    .replace(/(["']?(?:password|token|secret|authorization|cookie)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1[redacted]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
    .replace(/\b\d{6,}:[A-Za-z0-9_-]{20,}\b/g, '[redacted]')
    .replace(/\b[A-Za-z0-9_=-]{32,}(?:\.[A-Za-z0-9_=-]+)*\b/g, '[redacted]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    .slice(0, max);
}
const bool = v => typeof v === 'boolean' ? v : null;
const number = v => typeof v === 'number' && Number.isFinite(v) ? v : null;
const date = v => typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v).toISOString() : null;
function url(value, apiOrigin) {
  try {
    const u = new URL(value);
    if (u.origin !== apiOrigin || !['/api/v1/auth/guest/', '/api/v1/auth/me/'].includes(u.pathname)) return '[url omitted]';
    return `${u.origin}${u.pathname}`;
  } catch { return null; }
}
function original(error) {
  if (!error || typeof error !== 'object') return null;
  return {
    name: clean(error.name, 80), message: clean(error.message), stack: clean(error.stack),
    nativeCodeIfExposed: clean(error.nativeCodeIfExposed, 100),
    cause: error.cause ? { name: clean(error.cause.name, 80), message: clean(error.cause.message), code: clean(error.cause.code, 100) } : null,
  };
}
function bodyPreview(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return clean(value, 200);
  const out = {};
  for (const key of ['detail','message','code','error','non_field_errors']) {
    if (typeof value[key] === 'string' || typeof value[key] === 'number') out[key] = clean(value[key]);
    else if (Array.isArray(value[key])) out[key] = value[key].slice(0, 5).map(x => typeof x === 'string' ? clean(x, 300) : '[omitted]');
  }
  return out;
}
export function sanitizeReport(input, apiOrigin) {
  if (input?.schema !== 1 || !/^startup-[a-z0-9-]{8,70}$/.test(input.id || '') ||
      !/^SESSION-[A-Z_]+(?:-\d{3})?$/.test(input.supportCode || '') ||
      !Array.isArray(input.requests) || input.requests.length > 8) throw new Error('Invalid report');
  return {
    schema: 1, id: input.id, supportCode: input.supportCode,
    source: 'Unverified client diagnostic; correlate with server logs',
    createdAtUtc: date(input.createdAtUtc), receivedAtUtc: new Date().toISOString(),
    app: Object.fromEntries(['version','build','platform','osVersion','model'].map(k => [k, clean(input.app?.[k], 100)])),
    network: { type: clean(input.network?.type, 30), isConnected: bool(input.network?.isConnected), isInternetReachable: bool(input.network?.isInternetReachable) },
    requests: input.requests.map(r => ({
      startedAtUtc: date(r?.startedAtUtc), endedAtUtc: date(r?.endedAtUtc),
      durationMs: number(r?.durationMs), timeoutMs: number(r?.timeoutMs), attempt: number(r?.attempt),
      url: url(r?.url, apiOrigin), finalUrl: url(r?.finalUrl, apiOrigin),
      method: ['GET','POST'].includes(r?.method) ? r.method : null,
      stage: clean(r?.stage, 30), code: clean(r?.code, 30),
      authorizationPresent: bool(r?.authorizationPresent), responseReceived: bool(r?.responseReceived),
      httpStatus: number(r?.httpStatus), redirected: bool(r?.redirected), contentType: clean(r?.contentType, 100),
      originalError: original(r?.originalError), errorBodyPreview: bodyPreview(r?.errorBodyPreview),
    })),
  };
}

export function createRelay({ token, chatId, apiOrigin = 'https://185-129-48-150.sslip.io', fetchImpl = fetch, now = Date.now } = {}) {
  if (!token || !chatId) throw new Error('Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID on the server');
  // Fixed recipient. Never accept chat IDs, Telegram URLs or bot tokens from clients.
  const seen = new Map();
  const inFlight = new Set();
  let minute = -1, minuteCount = 0, day = -1, dayCount = 0;
  let intakeMinute = -1, intakeCount = 0;
  const send = (res, status, body, retryAfter) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(retryAfter ? { 'Retry-After': String(retryAfter) } : {}) });
    res.end(JSON.stringify(body));
  };
  const server = http.createServer({ maxHeaderSize: 8192 }, async (req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true });
    if (req.method !== 'POST' || req.url !== '/v1/startup-reports') return send(res, 404, { ok: false });
    if (!String(req.headers['content-type']).toLowerCase().startsWith('application/json')) return send(res, 415, { ok: false });
    if (Number(req.headers['content-length']) > MAX_BYTES) { req.resume(); return send(res, 413, { ok: false }); }
    const time = now();
    const m = Math.floor(time / 60000), d = Math.floor(time / 86400000);
    if (intakeMinute !== m) { intakeMinute = m; intakeCount = 0; }
    if (++intakeCount > 120) { req.resume(); return send(res, 429, { ok: false }, 60); }
    let raw;
    try {
      raw = await new Promise((resolve, reject) => {
        let size = 0, chunks = [];
        req.on('data', chunk => {
          size += chunk.length;
          if (size <= MAX_BYTES) chunks.push(chunk); else chunks = [];
        });
        req.on('end', () => size > MAX_BYTES ? reject(new Error('too-large')) : resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
      });
    } catch (e) { return send(res, e.message === 'too-large' ? 413 : 400, { ok: false }); }
    let report;
    try { report = sanitizeReport(JSON.parse(raw), apiOrigin); }
    catch { return send(res, 400, { ok: false }); }
    for (const [id, expires] of seen) if (expires < time) seen.delete(id);
    if (seen.has(report.id)) return send(res, 200, { ok: true, duplicate: true });
    if (inFlight.has(report.id)) return send(res, 429, { ok: false }, 60);
    if (minute !== m) { minute = m; minuteCount = 0; }
    if (day !== d) { day = d; dayCount = 0; }
    if (minuteCount >= 3 || dayCount >= 100) return send(res, 429, { ok: false }, dayCount >= 100 ? 3600 : 60);
    minuteCount++; dayCount++; inFlight.add(report.id);
    try {
      const last = report.requests.at(-1);
      const form = new FormData();
      form.set('chat_id', String(chatId));
      form.set('caption', [
        `Saqtau AI: ${report.supportCode}`,
        `${report.app.platform} ${report.app.osVersion}; ${report.app.model}`,
        `Version ${report.app.version} (${report.app.build})`,
        `${last?.method || '?'} ${last?.url || '?'}`,
        `HTTP ${last?.httpStatus ?? 'no response'}; ${last?.durationMs ?? '?'} ms`,
        `UTC ${report.createdAtUtc || '?'}`,
        `Report ${report.id} (client diagnostic)`,
      ].join('\n').slice(0, 1000));
      form.set('document', new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }), `${report.id}.json`);
      const response = await fetchImpl(`https://api.telegram.org/bot${token}/sendDocument`, {
        method: 'POST', body: form, signal: AbortSignal.timeout(8000),
      });
      const result = await response.json();
      if (!response.ok || result.ok !== true) throw new Error('Telegram delivery failed');
      seen.set(report.id, time + 86400000);
      return send(res, 200, { ok: true, id: report.id });
    } catch {
      // Never log the fetch exception: its URL contains the bot token.
      console.warn('Diagnostic delivery failed', report.id);
      return send(res, 503, { ok: false }, 60);
    } finally { inFlight.delete(report.id); }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.setTimeout(15000, socket => socket.destroy());
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createRelay({ token: process.env.TELEGRAM_BOT_TOKEN, chatId: process.env.TELEGRAM_CHAT_ID, apiOrigin: process.env.ALLOWED_API_ORIGIN || undefined });
  server.listen(Number(process.env.PORT || 8080), '0.0.0.0', () => console.log('Saqtau diagnostics relay listening'));
}
