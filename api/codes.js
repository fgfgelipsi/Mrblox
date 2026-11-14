// MrbloxScript — промокоды. Хранит коды в Upstash Redis (Vercel → Storage).
// Коды и сообщения хранятся зашифрованными; список и изменения — только с паролем админа.
const crypto = require('crypto');

const ADMIN_HASH = '0cde394567bb8dfb79a5b1acfa1692b665114ea009042973b664b731daca40f5';
const KEY = 'mrblox:codes';
const USED = 'mrblox:used';
const HEX64 = /^[a-f0-9]{64}$/;

// Находит адрес и токен базы при любом префиксе, который Vercel дал переменным
// (KV_REST_API_URL, UPSTASH_REDIS_REST_URL, STORAGE_KV_REST_API_URL и т.п.).
function findEnv() {
  const env = process.env;
  const keys = Object.keys(env);
  const pairs = [['KV_REST_API_URL', 'KV_REST_API_TOKEN'], ['REDIS_REST_URL', 'REDIS_REST_TOKEN']];
  for (const [u, t] of pairs) {
    const uk = keys.find(k => k.endsWith(u) && /^https:\/\//.test(env[k] || ''));
    if (uk) {
      const tk = uk.slice(0, -u.length) + t;
      if (env[tk]) return { url: env[uk], token: env[tk] };
    }
  }
  return { url: '', token: '' };
}

async function redis(cmd) {
  const { url, token } = findEnv();
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

    // Активация кода посетителем: каждый успешный запрос тратит одну активацию.
    if (req.method === 'GET' && h) {
      if (!HEX64.test(h)) return res.status(400).json({ error: 'bad_code' });
      const v = await redis(['HGET', KEY, h]);
      if (!v) return res.status(200).json({ doc: null });
      const d = JSON.parse(v);
      const max = Number(d.max) || 0;
      const used = await redis(['HINCRBY', USED, h, 1]);
      if (max > 0 && used > max) {
        await redis(['HINCRBY', USED, h, -1]);
        return res.status(200).json({ doc: null, exhausted: true });
      }
      return res.status(200).json({ doc: { iv: d.iv, ct: d.ct }, used, max });
    }

    if (!isAdmin(req)) return res.status(401).json({ error: 'auth' });

    if (req.method === 'GET') {
      const flat = (await redis(['HGETALL', KEY])) || [];
      const docs = [];
      for (let i = 1; i < flat.length; i += 2) {
        try { docs.push(JSON.parse(flat[i])); } catch (e) {}
      }
      const uflat = (await redis(['HGETALL', USED])) || [];
      const used = {};
      for (let i = 0; i < uflat.length; i += 2) used[uflat[i]] = Number(uflat[i + 1]) || 0;
      return res.status(200).json({ docs, used });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
      if (!HEX64.test(body.h || '') || !validDoc(body.doc)) return res.status(400).json({ error: 'bad_doc' });
      const d = body.doc;
      const max = Math.max(0, Math.min(1000000, Math.floor(Number(d.max) || 0)));
      const doc = { h: body.h, iv: d.iv, ct: d.ct, aiv: d.aiv, act: d.act, t: Number(d.t) || Date.now(), max };
      await redis(['HSET', KEY, body.h, JSON.stringify(doc)]);
      await redis(['HDEL', USED, body.h]); // новый или обновлённый код начинает счёт заново
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'DELETE') {
      if (!HEX64.test(h)) return res.status(400).json({ error: 'bad_code' });
      await redis(['HDEL', KEY, h]);
      await redis(['HDEL', USED, h]);
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'method' });
  } catch (e) {
    return res.status(e.status || 500).json({ error: e.message || 'server' });
  }
};
