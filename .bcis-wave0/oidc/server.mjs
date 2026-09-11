import { Provider } from 'oidc-provider';

const port = Number(process.env.PORT || 10000);
const externalHost = process.env.RENDER_EXTERNAL_HOSTNAME;
const issuer = process.env.OIDC_ISSUER || (externalHost ? `https://${externalHost}` : `http://localhost:${port}`);
const clientId = process.env.OIDC_CLIENT_ID || 'bcis-wave0-client';
const redirectUri = process.env.OIDC_REDIRECT_URI || `${issuer}/cb`;
const expectedClaims = ['tenant_id','roles','country_scope','project_scope','classification_ceiling'];

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

const localize = (url) => {
  const u = new URL(url);
  return `http://127.0.0.1:${port}${u.pathname}${u.search}`;
};

provider.listen(port, async () => {
  console.log(JSON.stringify({event:'OIDC_PROVIDER_READY',issuer,client_id:clientId,redirect_uri:redirectUri,claims_scope:'bcis',port}));
  try {
    const discoveryResp = await fetch(`http://127.0.0.1:${port}/.well-known/openid-configuration`, {headers:{host: externalHost || `localhost:${port}`}});
    if (!discoveryResp.ok) throw new Error(`DISCOVERY_HTTP_${discoveryResp.status}`);
    const d = await discoveryResp.json();
    const jwksResp = await fetch(localize(d.jwks_uri), {headers:{host: externalHost || `localhost:${port}`}});
    if (!jwksResp.ok) throw new Error(`JWKS_HTTP_${jwksResp.status}`);
    const jwks = await jwksResp.json();

    const checks = {
      issuer: d.issuer === issuer,
      authorization_endpoint: typeof d.authorization_endpoint === 'string',
      token_endpoint: typeof d.token_endpoint === 'string',
      jwks_nonempty: Array.isArray(jwks.keys) && jwks.keys.length > 0,
      code_flow: Array.isArray(d.response_types_supported) && d.response_types_supported.includes('code'),
      pkce_s256: Array.isArray(d.code_challenge_methods_supported) && d.code_challenge_methods_supported.includes('S256'),
      claims: expectedClaims.every(c => Array.isArray(d.claims_supported) && d.claims_supported.includes(c)),
    };
    const pass = Object.values(checks).every(Boolean);
    console.log(pass ? 'OIDC_SELFTEST_PASS' : 'OIDC_SELFTEST_FAIL', JSON.stringify({issuer,checks,claims_supported:d.claims_supported,jwks_key_count:jwks.keys?.length || 0}));
    if (!pass) process.exitCode = 2;
  } catch (err) {
    console.error('OIDC_SELFTEST_FAIL', JSON.stringify({issuer,error:err.message}));
    process.exitCode = 2;
  }
});
