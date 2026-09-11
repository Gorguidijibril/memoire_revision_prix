import http from 'node:http';
import { URL } from 'node:url';
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
  features: {
    claimsParameter: { enabled: true },
    devInteractions: { enabled: true },
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

server.listen(port, () => {
  console.log(JSON.stringify({
    event: 'OIDC_PROVIDER_V2_READY',
    issuer,
    client_id: clientId,
    redirect_uri: redirectUri,
    claims_parameter_enabled: true,
    claims: expectedClaims,
    port,
  }));
});
