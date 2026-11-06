// Tattoo studio booking — run: npm i && node --env-file=.env server.js  (Node 20+)
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { ADMIN_USER = 'admin', ADMIN_PASS = 'changeme', SECRET = 'change-this-secret', BREVO_API_KEY,
  SENDER_EMAIL, STUDIO_NAME = 'Ink Studio', STUDIO_ADDRESS = '', PORT = 3000 } = process.env;

const DB = path.join(__dirname, 'data.json');
const load = () => { try { return JSON.parse(fs.readFileSync(DB)); } catch { return []; } };
const save = d => fs.writeFileSync(DB, JSON.stringify(d, null, 2));
const hmac = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- auth (signed HttpOnly cookie, 12h) + basic brute-force limiter
const fails = new Map();
const auth = (req, res, next) => {
  const m = /(?:^|; )adm=([^;]+)/.exec(req.headers.cookie || '');
  if (m) { const [exp, sig] = m[1].split('.'); if (exp && sig && +exp > Date.now() && eq(sig, hmac(exp))) return next(); }
  res.status(401).json({ error: 'Please log in.' });
};
app.post('/api/login', (req, res) => {
  const ip = req.ip, f = fails.get(ip) || { n: 0, t: 0 };
  if (f.n >= 5 && Date.now() - f.t < 15 * 60e3) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { username = '', password = '' } = req.body || {};
  const ok = eq(hmac(username), hmac(ADMIN_USER)) & eq(hmac(password), hmac(ADMIN_PASS));
  if (!ok) { fails.set(ip, { n: f.n + 1, t: Date.now() }); return res.status(401).json({ error: 'Wrong username or password.' }); }
  fails.delete(ip);
  const exp = String(Date.now() + 12 * 3600e3);
  res.setHeader('Set-Cookie', `adm=${exp}.${hmac(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${req.secure ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 'adm=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ ok: true, studio: STUDIO_NAME }));

// ---- entries
const span = e => [`${e.date}T${e.start || '00:00'}`, `${e.endDate || e.date}T${e.end || '23:59'}`];
app.get('/api/entries', auth, (req, res) => res.json(load().sort((a, b) => span(a)[0].localeCompare(span(b)[0]))));

app.post('/api/entries', auth, async (req, res) => {
  const b = req.body || {}, type = b.type === 'off' ? 'off' : 'booking';
  const rx = { d: /^\d{4}-\d{2}-\d{2}$/, t: /^\d{2}:\d{2}$/ };
  const e = { id: crypto.randomUUID(), type, date: b.date, endDate: type === 'off' && b.endDate ? b.endDate : '',
    start: b.start || '', end: b.end || '', name: String(b.name || '').trim().slice(0, 100),
    email: String(b.email || '').trim().slice(0, 120), notes: String(b.notes || '').trim().slice(0, 500), emailed: false };
  if (!rx.d.test(e.date || '')) return res.status(400).json({ error: 'Pick a date.' });
  if (e.endDate && (!rx.d.test(e.endDate) || e.endDate < e.date)) return res.status(400).json({ error: 'End date must be on or after the start date.' });
  if (type === 'booking') {
    if (!e.name) return res.status(400).json({ error: "Enter the client's name." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.email)) return res.status(400).json({ error: "Enter a valid client email." });
    if (!rx.t.test(e.start) || !rx.t.test(e.end)) return res.status(400).json({ error: 'Set a start and end time.' });
  } else if ((e.start && !rx.t.test(e.start)) || (e.end && !rx.t.test(e.end))) return res.status(400).json({ error: 'Invalid time.' });
  const [s, en] = span(e);
  if (en <= s) return res.status(400).json({ error: 'End must be after start.' });
  const clash = load().find(o => { const [os, oe] = span(o); return s < oe && os < en; });
  if (clash) return res.status(409).json({ error: clash.type === 'off' ? 'That time overlaps an out-of-office block.' : `That time overlaps ${clash.name}'s booking.` });

  let emailNote = '';
  if (type === 'booking') {
    try { await sendConfirmation(e); e.emailed = true; } catch (err) { emailNote = err.message; }
  }
  const all = load(); all.push(e); save(all);
  res.json({ entry: e, emailNote });
});

app.delete('/api/entries/:id', auth, (req, res) => { save(load().filter(e => e.id !== req.params.id)); res.json({ ok: true }); });

app.post('/api/entries/:id/resend', auth, async (req, res) => {
  const all = load(), e = all.find(x => x.id === req.params.id);
  if (!e || e.type !== 'booking') return res.status(404).json({ error: 'Not found.' });
  try { await sendConfirmation(e); e.emailed = true; save(all); res.json({ ok: true }); }
  catch (err) { res.status(502).json({ error: err.message }); }
});

// ---- email (Brevo transactional API)
async function sendConfirmation(e) {
  if (!BREVO_API_KEY || !SENDER_EMAIL) throw new Error('Email not configured (set BREVO_API_KEY and SENDER_EMAIL).');
  const when = new Date(`${e.date}T00:00`).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#1a1a1a">
    <h2 style="margin:0 0 12px">Your booking is confirmed</h2>
    <p>Hi ${esc(e.name)}, your appointment at <b>${esc(STUDIO_NAME)}</b> is confirmed.</p>
    <p style="background:#f4f4f4;padding:14px;border-radius:8px"><b>${esc(when)}</b><br>${esc(e.start)} – ${esc(e.end)}${STUDIO_ADDRESS ? `<br>${esc(STUDIO_ADDRESS)}` : ''}</p>
    ${e.notes ? `<p>Notes: ${esc(e.notes)}</p>` : ''}
    <p>Payment is made in person at the studio. To change or cancel, just reply to this email.</p></div>`;
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST', headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: STUDIO_NAME, email: SENDER_EMAIL }, to: [{ email: e.email, name: e.name }],
      replyTo: { email: SENDER_EMAIL }, subject: `Booking confirmed – ${when}, ${e.start}`, htmlContent: html })
  });
  if (!r.ok) throw new Error(`Email failed (Brevo ${r.status}).`);
}

app.listen(PORT, () => console.log(`Booking site on http://localhost:${PORT}`));
