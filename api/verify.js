const crypto = require('crypto');

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = v;
  });
  return out;
}

function verify(cookieValue, secret) {
  if (!cookieValue || typeof cookieValue !== 'string') return null;
  const lastDot = cookieValue.lastIndexOf('.');
  if (lastDot === -1) return null;
  const token = cookieValue.slice(0, lastDot);
  const sig = cookieValue.slice(lastDot + 1);

  const expectedSig = crypto.createHmac('sha256', secret).update(token).digest('hex');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  return payload;
}

module.exports = async function handler(req, res) {
  const { AUTH_SECRET } = process.env;
  if (!AUTH_SECRET) {
    res.status(200).json({ ok: false });
    return;
  }
  const cookies = parseCookies(req.headers.cookie);
  const payload = verify(cookies.sheetscrub_session, AUTH_SECRET);
  if (!payload) {
    res.status(200).json({ ok: false });
    return;
  }
  res.status(200).json({ ok: true, username: payload.u });
};
