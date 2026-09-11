import http from 'node:http';
import crypto from 'node:crypto';
import { URL, URLSearchParams } from 'node:url';
import { Provider } from 'oidc-provider';

const port = Number(process.env.PORT || 10000);
const externalHost = process.env.RENDER_EXTERNAL_HOSTNAME;
const issuer = process.env.OIDC_ISSUER || (externalHost ? `https://${externalHost}` : `http://localhost:${port}`);
const clientId = process.env.OIDC_CLIENT_ID || 'bcis-wave0-client';
const redirectUri = process.env.OIDC_REDIRECT_URI || `${issuer}/cb`;
const expectedClaims = ['tenant_id','roles','country_scope','project_scope','classification_ceiling'];
const accountId = 'wave0-user';

const provider = new Provider(issuer, {
  clients: [{
    client_id: clientId,
    token_endpoint_auth_method: 'none',
    application_type: 'web',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: [redirectUri],
  }],
  pkce: { required: () => true, methods: ['S256'] },
  claims: {
    openid: ['sub'],
    profile: ['name'],
    bcis: expectedClaims,
  },
  findAccount: async (_ctx, id) => ({
    accountId: id,
    claims: async () => ({
      sub: id,
      name: 'BCI-S Wave0 User',
      tenant_id: '11111111-1111-4111-8111-111111111111',
      roles: ['ESTIMATOR'],
      country_scope: ['SN'],
      project_scope: ['22222222-2222-4222-8222-222222222222'],
      classification_ceiling: 'CONFIDENTIAL',
    }),
  }),
  features: { devInteractions: { enabled: true } },
  ttl: { AccessToken: 600, AuthorizationCode: 60, IdToken: 600 },
});

provider.proxy = true;
provider.on('server_error', (_ctx, err) => console.error('OIDC_SERVER_ERROR', err));

const oidcCallback = provider.callback();
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const login = url.pathname.match(/^\/interaction\/([^/]+)\/login$/);
    const confirm = url.pathname.match(/^\/interaction\/([^/]+)\/confirm$/);

    if (req.method === 'POST' && login) {
      const details = await provider.interactionDetails(req, res);
      if (details.prompt?.name !== 'login') throw new Error(`EXPECTED_LOGIN_PROMPT_GOT_${details.prompt?.name}`);
      await provider.interactionFinished(req, res, { login: { accountId } }, { mergeWithLastSubmission: false });
      return;
    }

    if (req.method === 'POST' && confirm) {
      const details = await provider.interactionDetails(req, res);
      if (details.prompt?.name !== 'consent') throw new Error(`EXPECTED_CONSENT_PROMPT_GOT_${details.prompt?.name}`);
      const { params, session, prompt } = details;
      let grantId = details.grantId;
      let grant = grantId ? await provider.Grant.find(grantId) : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
      if (prompt.details.missingOIDCScope) grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
      if (prompt.details.missingOIDCClaims) grant.addOIDCClaims(prompt.details.missingOIDCClaims);
      grantId = await grant.save();
      const consent = details.grantId ? {} : { grantId };
      await provider.interactionFinished(req, res, { consent }, { mergeWithLastSubmission: true });
      return;
    }

    oidcCallback(req, res);
  } catch (err) {
    console.error('OIDC_ROUTE_ERROR', err);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.end('internal error');
    }
  }
});

const localize = (url) => {
  const u = new URL(url, issuer);
  return `http://127.0.0.1:${port}${u.pathname}${u.search}`;
};

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
      const cookies = typeof resp.headers.getSetCookie === 'function' ? resp.headers.getSetCookie() : (resp.headers.get('set-cookie') ? [resp.headers.get('set-cookie')] : []);
      for (const raw of cookies) {
        const first = raw.split(';', 1)[0];
        const eq = first.indexOf('=');
        if (eq > 0) jar.set(first.slice(0, eq), first.slice(eq + 1));
      }
    },
  };
}

async function requestLocal(url, jar, options = {}) {
  const headers = jar.apply({ ...(options.headers || {}), host: externalHost || `localhost:${port}` });
  const resp = await fetch(localize(url), { ...options, headers, redirect: 'manual' });
  jar.capture(resp);
  return resp;
}

async function followInteractionFlow(discovery) {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(sha256(verifier));
  const state = b64url(crypto.randomBytes(16));
  const nonce = b64url(crypto.randomBytes(16));
  const auth = new URL(discovery.authorization_endpoint);
  auth.search = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'openid bcis',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  }).toString();

  const jar = makeCookieJar();
  let resp = await requestLocal(auth.toString(), jar);
  let location = resp.headers.get('location');
  if (!location || !location.includes('/interaction/')) throw new Error(`AUTH_NO_INTERACTION_REDIRECT:${resp.status}:${location}`);
  let uid = new URL(location, issuer).pathname.split('/').filter(Boolean)[1];

  resp = await requestLocal(`${issuer}/interaction/${uid}/login`, jar, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'login=wave0' });
  location = resp.headers.get('location');
  if (!location) throw new Error(`LOGIN_NO_REDIRECT:${resp.status}`);

  resp = await requestLocal(location, jar);
  location = resp.headers.get('location');
  if (!location || !location.includes('/interaction/')) throw new Error(`CONSENT_NO_INTERACTION_REDIRECT:${resp.status}:${location}`);
  uid = new URL(location, issuer).pathname.split('/').filter(Boolean)[1];

  resp = await requestLocal(`${issuer}/interaction/${uid}/confirm`, jar, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '' });
  location = resp.headers.get('location');
  if (!location) throw new Error(`CONSENT_NO_REDIRECT:${resp.status}`);

  resp = await requestLocal(location, jar);
  location = resp.headers.get('location');
  if (!location) throw new Error(`AUTH_RESUME_NO_CALLBACK:${resp.status}`);
  const cb = new URL(location, issuer);
  const code = cb.searchParams.get('code');
  if (!code) throw new Error(`CALLBACK_CODE_MISSING:${location}`);
  if (cb.searchParams.get('state') !== state) throw new Error('STATE_MISMATCH');

  const tokenResp = await requestLocal(discovery.token_endpoint, makeCookieJar(), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
  });
  if (!tokenResp.ok) throw new Error(`TOKEN_HTTP_${tokenResp.status}:${await tokenResp.text()}`);
  const tokens = await tokenResp.json();
  if (!tokens.id_token) throw new Error('ID_TOKEN_MISSING');
  return { tokens, nonce };
}

async function verifyIdToken(idToken, jwks, nonce) {
  const [h,p,s] = idToken.split('.');
  if (!h || !p || !s) throw new Error('JWT_FORMAT');
  const header = decodeJsonPart(h);
  const payload = decodeJsonPart(p);
  const jwk = jwks.keys.find(k => !header.kid || k.kid === header.kid);
  if (!jwk) throw new Error('JWK_NOT_FOUND');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const algMap = { RS256: 'RSA-SHA256', PS256: 'RSA-SHA256', ES256: 'SHA256' };
  const algorithm = algMap[header.alg];
  if (!algorithm) throw new Error(`UNSUPPORTED_ALG_${header.alg}`);
  const ok = crypto.verify(algorithm, Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('JWT_SIGNATURE_INVALID');
  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const checks = {
    signature: ok,
    issuer: payload.iss === issuer,
    audience: aud.includes(clientId),
    expiry: Number(payload.exp) > now,
    nonce: payload.nonce === nonce,
    subject: payload.sub === accountId,
    bcis_claims: expectedClaims.every(c => Object.prototype.hasOwnProperty.call(payload, c)),
  };
  return { header, payload, checks, pass: Object.values(checks).every(Boolean) };
}

server.listen(port, async () => {
  console.log(JSON.stringify({event:'OIDC_PROVIDER_READY',issuer,client_id:clientId,redirect_uri:redirectUri,claims_scope:'bcis',port}));
  try {
    const discoveryResp = await fetch(`http://127.0.0.1:${port}/.well-known/openid-configuration`, {headers:{host: externalHost || `localhost:${port}`}});
    if (!discoveryResp.ok) throw new Error(`DISCOVERY_HTTP_${discoveryResp.status}`);
    const d = await discoveryResp.json();
    const jwksResp = await fetch(localize(d.jwks_uri), {headers:{host: externalHost || `localhost:${port}`}});
    if (!jwksResp.ok) throw new Error(`JWKS_HTTP_${jwksResp.status}`);
    const jwks = await jwksResp.json();

    const metadataChecks = {
      issuer: d.issuer === issuer,
      authorization_endpoint: typeof d.authorization_endpoint === 'string',
      token_endpoint: typeof d.token_endpoint === 'string',
      jwks_nonempty: Array.isArray(jwks.keys) && jwks.keys.length > 0,
      code_flow: Array.isArray(d.response_types_supported) && d.response_types_supported.includes('code'),
      pkce_s256: Array.isArray(d.code_challenge_methods_supported) && d.code_challenge_methods_supported.includes('S256'),
      claims: expectedClaims.every(c => Array.isArray(d.claims_supported) && d.claims_supported.includes(c)),
    };
    const metadataPass = Object.values(metadataChecks).every(Boolean);
    console.log(metadataPass ? 'OIDC_SELFTEST_PASS' : 'OIDC_SELFTEST_FAIL', JSON.stringify({issuer,checks:metadataChecks,claims_supported:d.claims_supported,jwks_key_count:jwks.keys?.length || 0}));
    if (!metadataPass) throw new Error('METADATA_GATE_FAIL');

    const { tokens, nonce } = await followInteractionFlow(d);
    const verified = await verifyIdToken(tokens.id_token, jwks, nonce);
    const safePayload = {
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
    console.log(verified.pass ? 'OIDC_TOKEN_SELFTEST_PASS' : 'OIDC_TOKEN_SELFTEST_FAIL', JSON.stringify({checks:verified.checks,header:{alg:verified.header.alg,kid:verified.header.kid},claims:safePayload}));
    if (!verified.pass) process.exitCode = 3;
  } catch (err) {
    console.error('OIDC_TOKEN_SELFTEST_FAIL', JSON.stringify({issuer,error:err.message}));
    process.exitCode = 3;
  }
});
