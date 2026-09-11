import { Provider } from 'oidc-provider';

const port = Number(process.env.PORT || 10000);
const externalHost = process.env.RENDER_EXTERNAL_HOSTNAME;
const issuer = process.env.OIDC_ISSUER || (externalHost ? `https://${externalHost}` : `http://localhost:${port}`);
const clientId = process.env.OIDC_CLIENT_ID || 'bcis-wave0-client';
const redirectUri = process.env.OIDC_REDIRECT_URI || `${issuer}/cb`;

const provider = new Provider(issuer, {
  clients: [
    {
      client_id: clientId,
      token_endpoint_auth_method: 'none',
      application_type: 'web',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      redirect_uris: [redirectUri],
    },
  ],
  pkce: {
    required: () => true,
    methods: ['S256'],
  },
  claims: {
    openid: ['sub'],
    profile: ['name'],
    bcis: [
      'tenant_id',
      'roles',
      'country_scope',
      'project_scope',
      'classification_ceiling',
    ],
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
  features: {
    devInteractions: { enabled: true },
  },
  ttl: {
    AccessToken: 600,
    AuthorizationCode: 60,
    IdToken: 600,
  },
});

provider.proxy = true;
provider.on('server_error', (_ctx, err) => {
  console.error('OIDC_SERVER_ERROR', err);
});

provider.listen(port, () => {
  console.log(JSON.stringify({
    event: 'OIDC_PROVIDER_READY',
    issuer,
    client_id: clientId,
    redirect_uri: redirectUri,
    claims_scope: 'bcis',
    port,
  }));
});
