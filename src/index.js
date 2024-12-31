import { Hono } from "hono";
import { env } from 'hono/adapter'
import { getConnInfo } from 'hono/cloudflare-workers'
import { bearerAuth } from 'hono/bearer-auth'
import { cors } from 'hono/cors'
import { HTTPException } from 'hono/http-exception'
import { WorkOS } from '@workos-inc/node';
import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
import { createCustomToken, pemToArrayBuffer } from './utils';

const app = new Hono();

app.use('*', cors())

app.use(async (c, next) => {
  const { WORKOS_SECRET } = env(c);
  c.set('workos', new WorkOS(WORKOS_SECRET));
  await next()
})

app.use(
  '/auth/*',
  bearerAuth({
    verifyToken: async (token, c) => {
      const { WORKOS_CLIENT_ID } = env(c);
      const workos = c.get('workos');
      const JWKS = createRemoteJWKSet(
        new URL(workos.userManagement.getJwksUrl(WORKOS_CLIENT_ID)),
      );
      const res = await jwtVerify(token, JWKS);
      if (!res) {
        return false
      }
      c.set('jwtPayload', res.payload);
      return true
    },
  })
)

app.post("/create-account", async (c) => {
  const data = await c.req.json();

  const workos = c.get('workos');

  // const user = await workos.userManagement.createUser({
  //   email: 'marcelina@example.com',
  //   password: 'i8uv6g34kd490s',
  //   firstName: 'Marcelina',
  //   lastName: 'Davis',
  // });


})

app.get("/auth-redirect", (c) => {
  const workos = c.get('workos');
  const { WORKOS_CLIENT_ID } = env(c);

  const { redirect_uri, provider } = c.req.query()

  let providerForWorkOS = 'authkit';

  switch (provider) {
    case 'github.com':
      providerForWorkOS = 'GitHubOAuth'
      break
    case 'google.com':
      providerForWorkOS = 'GoogleOAuth';
      break
  }

  const authorizationUrl = workos.userManagement.getAuthorizationUrl({
    // Specify that we'd like AuthKit to handle the authentication flow
    provider: providerForWorkOS,

    // The callback endpoint that WorkOS will redirect to after a user authenticates
    redirectUri: redirect_uri || 'http://localhost:8787/callback',
    clientId: WORKOS_CLIENT_ID,
  });

  // Redirect the user to the AuthKit sign-in page
  return c.redirect(authorizationUrl);
})

app.post("/token", async (c) => {
  const req = c.req;
  const info = getConnInfo(c)
  const { WORKOS_CLIENT_ID, SERVICE_ACCOUNT_JSON } = env(c);
  const db = c.env.DB; // DB is the binding name for your D1 database

  try {

    const { code, error, refresh_token } = await req.parseBody()

    if (error) {
      //some sort of errors
      throw new HTTPException(400, { message: 'Error' })
    } else {
      const workos = c.get('workos');

      if (refresh_token) {
        const  {accessToken, refreshToken } = await workos.userManagement.authenticateWithRefreshToken({
          clientId: WORKOS_CLIENT_ID,
          refreshToken: refresh_token,
          ipAddress: info.remote.address,
          userAgent: c.req.header('User-Agent'),
        });

        return c.json({
          access_token: accessToken,
          refresh_token: refreshToken,
        })
      }

      const  {accessToken, organizationId, user, refreshToken } = await workos.userManagement.authenticateWithCode({
        clientId: WORKOS_CLIENT_ID,
        code: code,
        ipAddress: info.remote.address,
        userAgent: c.req.header('User-Agent'),
      });

      const decoded = decodeJwt(accessToken);

      // go and look up the organizationId in the db
      const orgData = await db.prepare(`SELECT * FROM workos_organisation_lookup WHERE workos_organisation_id = ?`).bind(organizationId).run()

      const userData = await db.prepare(`SELECT * FROM workos_user_lookup WHERE workos_user_id = ?`).bind(user.id).run()

      console.log(orgData, userData)

      const idToken = await createCustomToken(JSON.parse(SERVICE_ACCOUNT_JSON), userData.results[0].firebase_user_id, {
        orgId: orgData.results[0].firestore_org_id,
        roles: [decoded.role]
      })

      return c.json({
        access_token: accessToken,
        id_token: accessToken,
        refresh_token: refreshToken,
        firebase_token: idToken,
      })
    }
  } catch (err) {
    console.error(err)
    throw new HTTPException(500, { message: 'Error' })
  }
});

export default app;