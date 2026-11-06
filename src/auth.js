import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const TOKEN_TTL_MS = 60 * 60 * 1000;
const signingKey = randomBytes(32);
const users = new Map();

export function addUser(username, password) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  users.set(username, { salt, hash });
}

export function login(username, password, now = Date.now()) {
  const user = users.get(username);
  if (!user) {
    return null;
  }
  const hash = scryptSync(password, user.salt, 64).toString('hex');
  const a = Buffer.from(hash);
  const b = Buffer.from(user.hash);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return null;
  }
  return issueToken(username, now);
}

export function verifyToken(token, now = Date.now()) {
  if (typeof token !== 'string') {
    return null;
  }
  const [payload, signature] = token.split('.');
  if (!payload || !signature) {
    return null;
  }
  const expectedSig = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return null;
  }
  try {
    const { sub, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof exp !== 'number' || now >= exp) {
      return null;
    }
    return sub;
  } catch {
    return null;
  }
}

function issueToken(username, now) {
  const payload = Buffer.from(JSON.stringify({ sub: username, exp: now + TOKEN_TTL_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function sign(payload) {
  return createHmac('sha256', signingKey).update(payload).digest('base64url');
}

export function _resetForTests() {
  users.clear();
}
