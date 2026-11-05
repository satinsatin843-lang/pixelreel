const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const Database = require('better-sqlite3');

const { JWT_SECRET, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, REPLICATE_API_TOKEN, PORT = 3000 } = process.env;
if (!JWT_SECRET) throw new Error('JWT_SECRET set karo');

const db = new Database('pixelreel.db');
db.exec(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE, hash TEXT,
  created_at INTEGER, paid_until INTEGER DEFAULT 0)`);

const rzp = new Razorpay({ key_id: RAZORPAY_KEY_ID || 'x', key_secret: RAZORPAY_KEY_SECRET || 'x' });
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname + '/public'));

const DAY = 864e5;
const sign = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '30d' });

app.post('/api/signup', (req, res) => {
  const { email, password } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Sahi email aur 6+ character password do' });
  try {
    const r = db.prepare('INSERT INTO users(email,hash,created_at) VALUES(?,?,?)')
      .run(email.toLowerCase(), bcrypt.hashSync(password, 10), Date.now());
    res.json({ token: sign({ id: r.lastInsertRowid }) });
  } catch { res.status(409).json({ error: 'Email pehle se registered hai' }); }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.hash))
    return res.status(401).json({ error: 'Email ya password galat hai' });
  res.json({ token: sign(u) });
});

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(t, JWT_SECRET).id);
    if (!req.user) throw 0;
    next();
  } catch { res.status(401).json({ error: 'Login karein' }); }
}
const status = u => {
  const trialEnds = u.created_at + 3 * DAY, now = Date.now();
  const paid = u.paid_until > now;
  return { paid, trialDaysLeft: Math.max(0, Math.ceil((trialEnds - now) / DAY)),
           active: paid || now < trialEnds };
};
const gate = (req, res, next) =>
  status(req.user).active ? next() : res.status(402).json({ error: 'Trial khatam. ₹20 plan lein.' });

app.get('/api/me', auth, (req, res) => res.json({ email: req.user.email, ...status(req.user) }));

app.post('/api/pay/create', auth, async (req, res) => {
  try {
    const order = await rzp.orders.create({ amount: 2000, currency: 'INR', receipt: 'u' + req.user.id + '_' + Date.now() });
    res.json({ orderId: order.id, keyId: RAZORPAY_KEY_ID, amount: 2000 });
  } catch { res.status(502).json({ error: 'Payment shuru nahi hui' }); }
});

app.post('/api/pay/verify', auth, (req, res) => {
  const { razorpay_order_id: o, razorpay_payment_id: p, razorpay_signature: s } = req.body || {};
  const expect = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(o + '|' + p).digest('hex');
  if (expect !== s) return res.status(400).json({ error: 'Payment verify nahi hua' });
  const base = Math.max(Date.now(), req.user.paid_until);
  db.prepare('UPDATE users SET paid_until=? WHERE id=?').run(base + 30 * DAY, req.user.id);
  res.json({ ok: true });
});

app.post('/api/image', auth, gate, async (req, res) => {
  try {
    const prompt = String(req.body.prompt || '').slice(0, 400);
    if (!prompt) return res.status(400).json({ error: 'Prompt likho' });
    const url = 'https://image.pollinations.ai/prompt/' + encodeURIComponent(prompt) + '?width=768&height=768&nologo=true';
    const r = await fetch(url);
    if (!r.ok) return res.status(502).json({ error: 'Image service busy, dobara try karo' });
    const buf = Buffer.from(await r.arrayBuffer());
    res.json({ image: 'data:image/jpeg;base64,' + buf.toString('base64') });
  } catch { res.status(502).json({ error: 'Image nahi ban payi, dobara try karo' }); }
});

const VIDEO_MODEL = 'minimax/video-01';
app.post('/api/video', auth, gate, async (req, res) => {
  try {
    if (!REPLICATE_API_TOKEN) return res.status(503).json({ error: 'Video abhi chalu nahi hai' });
    const prompt = String(req.body.prompt || '').slice(0, 400);
    const r = await fetch(`https://api.replicate.com/v1/models/${VIDEO_MODEL}/predictions`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + REPLICATE_API_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: { prompt } })
    });
    const j = await r.json();
    res.status(r.ok ? 200 : 502).json(r.ok ? { id: j.id } : { error: 'Video start nahi hui' });
  } catch { res.status(502).json({ error: 'Video start nahi hui' }); }
});

app.get('/api/video/:id', auth, gate, async (req, res) => {
  try {
    const r = await fetch('https://api.replicate.com/v1/predictions/' + encodeURIComponent(req.params.id),
      { headers: { Authorization: 'Bearer ' + REPLICATE_API_TOKEN } });
    const j = await r.json();
    res.json({ status: j.status, url: j.output || null });
  } catch { res.status(502).json({ error: 'Video ki jaankari nahi mili' }); }
});

app.listen(PORT, () => console.log('PixelReel API on ' + PORT));
