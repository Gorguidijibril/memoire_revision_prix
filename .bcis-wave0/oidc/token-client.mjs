import crypto from 'node:crypto';

const issuer = process.env.OIDC_ISSUER || 'https://bcis-wave0-oidc-selftest.onrender.com';
const clientId = process.env.OIDC_CLIENT_ID || 'bcis-wave0-client';
const redirectUri = process.env.OIDC_REDIRECT_URI || `${issuer}/cb`;
const expectedClaims = ['tenant_id','roles','country_scope','project_scope','classification_ceiling'];

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
const decodeJsonPart = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

function makeCookieJar() {
  const jar = new Map();
  return {
    apply(headers = {}) {
      if (jar.size) headers.cookie = [...jar.entries()].map(([k,v]) => `${k}=${v}`).join('; ');
      return headers;
    },
    capture(resp) {
      const cookies = typeof resp.headers.getSetCookie === 'function'
        ? resp.headers.getSetCookie()
        : (resp.headers.get('set-cookie') ? [resp.headers.get('set-cookie')] : []);
      for (const raw of cookies) {
        const first = raw.split(';', 1)[0];
        const eq = first.indexOf('=');
        if (eq > 0) jar.set(first.slice(0, eq), first.slice(eq + 1));
      }
    },
  };
}

async function req(url, jar, options = {}) {
  const headers = jar.apply({ ...(options.headers || {}) });
  const resp = await fetch(url, { ...options, headers, redirect: 'manual' });
  jar.capture(resp);
  return resp;
}

async function getDiscovery() {
  const r = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!r.ok) throw new Error(`DISCOVERY_HTTP_${r.status}`);
  return r.json();
}

async function getJwks(uri) {
  const r = await fetch(uri);
  if (!r.ok) throw new Error(`JWKS_HTTP_${r.status}`);
  return r.json();
}

async function getToken(discovery) {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(sha256(verifier));
  const state = b64url(crypto.randomBytes(16));
  const nonce = b64url(crypto.randomBytes(16));
  const requestedClaims = Object.fromEntries(expectedClaims.map((c) => [c, null]));

  const auth = new URL(discovery.authorization_endpoint);
  auth.search = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'openid bcis',
    claims: JSON.stringify({ id_token: requestedClaims }),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  }).toString();

  const jar = makeCookieJar();
  let resp = await req(auth.toString(), jar);
  let location = resp.headers.get('location');
  if (!location || !location.includes('/interaction/')) throw new Error(`AUTH_NO_INTERACTION:${resp.status}:${location}`);
  let uid = new URL(location, issuer).pathname.split('/').filter(Boolean)[1];

  resp = await req(`${issuer}/interaction/${uid}/login`, jar, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'login=wave0',
  });
  location = resp.headers.get('location');
  if (!location) throw new Error(`LOGIN_NO_REDIRECT:${resp.status}`);

  resp = await req(new URL(location, issuer).toString(), jar);
  location = resp.headers.get('location');
  if (!location || !location.includes('/interaction/')) throw new Error(`CONSENT_NO_INTERACTION:${resp.status}:${location}`);
  uid = new URL(location, issuer).pathname.split('/').filter(Boolean)[1];

  resp = await req(`${issuer}/interaction/${uid}/confirm`, jar, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: '',
  });
  location = resp.headers.get('location');
  if (!location) throw new Error(`CONSENT_NO_REDIRECT:${resp.status}`);

  resp = await req(new URL(location, issuer).toString(), jar);
  location = resp.headers.get('location');
  if (!location) throw new Error(`AUTH_RESUME_NO_CALLBACK:${resp.status}`);

  const cb = new URL(location, issuer);
  const code = cb.searchParams.get('code');
  if (!code) throw new Error(`CALLBACK_CODE_MISSING:${location}`);
  if (cb.searchParams.get('state') !== state) throw new Error('STATE_MISMATCH');

  const tokenResp = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }).toString(),
  });
  if (!tokenResp.ok) throw new Error(`TOKEN_HTTP_${tokenResp.status}:${await tokenResp.text()}`);
  const tokens = await tokenResp.json();
  if (!tokens.id_token) throw new Error('ID_TOKEN_MISSING');
  return { tokens, nonce };
}

function verifyToken(idToken, jwks, nonce) {
  const [h,p,s] = idToken.split('.');
  if (!h || !p || !s) throw new Error('JWT_FORMAT');
  const header = decodeJsonPart(h);
  const payload = decodeJsonPart(p);
  const jwk = jwks.keys.find((k) => !header.kid || k.kid === header.kid);
  if (!jwk) throw new Error('JWK_NOT_FOUND');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const algMap = { RS256: 'RSA-SHA256', ES256: 'SHA256' };
  const algorithm = algMap[header.alg];
  if (!algorithm) throw new Error(`UNSUPPORTED_ALG_${header.alg}`);
  const signature = crypto.verify(algorithm, Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'));
  const now = Math.floor(Date.now()/1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const checks = {
    signature,
    issuer: payload.iss === issuer,
    audience: aud.includes(clientId),
    expiry: Number(payload.exp) > now,
    nonce: payload.nonce === nonce,
    subject: payload.sub === 'wave0-user',
    bcis_claims: expectedClaims.every((c) => Object.prototype.hasOwnProperty.call(payload, c)),
  };
  return { header, payload, checks, pass: Object.values(checks).every(Boolean) };
}

try {
  const discovery = await getDiscovery();
  const jwks = await getJwks(discovery.jwks_uri);
  const { tokens, nonce } = await getToken(discovery);
  const verified = verifyToken(tokens.id_token, jwks, nonce);
  const safeClaims = {
    iss: verified.payload.iss,
    aud: verified.payload.aud,
    sub: verified.payload.sub,
    exp: verified.payload.exp,
    tenant_id: verified.payload.tenant_id,
    roles: verified.payload.roles,
    country_scope: verified.payload.country_scope,
    project_scope: verified.payload.project_scope,
    classification_ceiling: verified.payload.classification_ceiling,
  };
  console.log(verified.pass ? 'OIDC_SIGNED_TOKEN_GATE_PASS' : 'OIDC_SIGNED_TOKEN_GATE_FAIL', JSON.stringify({ checks: verified.checks, alg: verified.header.alg, kid: verified.header.kid, claims: safeClaims }));
  if (!verified.pass) process.exit(2);
} catch (err) {
  console.error('OIDC_SIGNED_TOKEN_GATE_FAIL', JSON.stringify({ error: err.message }));
  process.exit(2);
}
