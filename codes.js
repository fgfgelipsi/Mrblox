// MrbloxScript — промокоды. Хранит коды в Upstash Redis (Vercel → Storage).
// Коды и сообщения хранятся зашифрованными; список и изменения — только с паролем админа.
const crypto = require('crypto');

const ADMIN_HASH = '0cde394567bb8dfb79a5b1acfa1692b665114ea009042973b664b731daca40f5';
const KEY = 'mrblox:codes';
const HEX64 = /^[a-f0-9]{64}$/;

async function redis(cmd) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) { const e = new Error('no_db'); e.status = 503; throw e; }
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

function isAdmin(req) {
  const pw = req.headers['x-admin-pass'];
  if (!pw || typeof pw !== 'string') return false;
  const h = crypto.createHash('sha256').update('mrblox|' + pw).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(ADMIN_HASH));
}

function validDoc(doc) {
  if (!doc || typeof doc !== 'object') return false;
  for (const k of ['iv', 'ct', 'aiv', 'act']) {
    if (typeof doc[k] !== 'string' || doc[k].length > 8000 || !/^[A-Za-z0-9+/=]+$/.test(doc[k])) return false;
  }
  return true;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const h = req.query && typeof req.query.h === 'string' ? req.query.h : '';

    if (req.method === 'GET' && h) {
      if (!HEX64.test(h)) return res.status(400).json({ error: 'bad_code' });
      const v = await redis(['HGET', KEY, h]);
      return res.status(200).json({ doc: v ? JSON.parse(v) : null });
    }

    if (!isAdmin(req)) return res.status(401).json({ error: 'auth' });

    if (req.method === 'GET') {
      const flat = (await redis(['HGETALL', KEY])) || [];
      const docs = [];
      for (let i = 1; i < flat.length; i += 2) {
        try { docs.push(JSON.parse(flat[i])); } catch (e) {}
      }
      return res.status(200).json({ docs });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
      if (!HEX64.test(body.h || '') || !validDoc(body.doc)) return res.status(400).json({ error: 'bad_doc' });
      const d = body.doc;
      const doc = { h: body.h, iv: d.iv, ct: d.ct, aiv: d.aiv, act: d.act, t: Number(d.t) || Date.now() };
      await redis(['HSET', KEY, body.h, JSON.stringify(doc)]);
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'DELETE') {
      if (!HEX64.test(h)) return res.status(400).json({ error: 'bad_code' });
      await redis(['HDEL', KEY, h]);
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'method' });
  } catch (e) {
    return res.status(e.status || 500).json({ error: e.message || 'server' });
  }
};
