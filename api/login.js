const crypto = require('crypto');

function sign(payload, secret) {
  const token = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(token).digest('hex');
  return token + '.' + sig;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'Method not allowed' });
    return;
  }

  const { AUTH_USERNAME, AUTH_PASSWORD, AUTH_SECRET } = process.env;
  if (!AUTH_USERNAME || !AUTH_PASSWORD || !AUTH_SECRET) {
    // Fails closed: if env vars aren't set, nobody gets in (not "anyone gets in").
    res.status(500).json({ ok: false, error: 'Server auth is not configured.' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const { username, password } = body || {};

  // Constant-time-ish comparison: both credentials must match exactly.
  const userOk = typeof username === 'string' && username === AUTH_USERNAME;
  const passOk = typeof password === 'string' && password === AUTH_PASSWORD;

  if (!userOk || !passOk) {
    res.status(401).json({ ok: false, error: 'Incorrect username or password.' });
    return;
  }

  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7-day session
  const token = sign({ u: username, exp }, AUTH_SECRET);

  res.setHeader(
    'Set-Cookie',
    `sheetscrub_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${7 * 24 * 60 * 60}`
  );
  res.status(200).json({ ok: true });
};
