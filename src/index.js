import { Hono } from "hono";
import { env } from 'hono/adapter'
import { getConnInfo } from 'hono/cloudflare-workers'
import { bearerAuth } from 'hono/bearer-auth'
import { cors } from 'hono/cors'
import { HTTPException } from 'hono/http-exception'
import { setCookie } from 'hono/cookie';
import { WorkOS } from '@workos-inc/node';
import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
// import { initializeApp, applicationDefault, cert } from 'firebase-admin/app';
// import { getFirestore, Timestamp, FieldValue, Filter } from 'firebase-admin/firestore';

import { createCustomToken, pemToArrayBuffer } from './utils';
// import serviceAccount from '../firebase-private-key.json';

// Initialize firebase
// initializeApp({
//   credential: cert(serviceAccount)
// });
// const db = getFirestore();

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

  console.log('redirect_uri', redirect_uri, provider)

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

app.get('/callback', async (c) => {
  const workos = c.get('workos');
  const { WORKOS_CLIENT_ID } = env(c);

  // The authorization code returned by AuthKit
  const { code } = c.req.query();

  if (!code) {
    return c.json({ err: 'No code provided' }, 400);
  }

  try {
    const { user, sealedSession } = await workos.userManagement.authenticateWithCode({
      code,
      clientId: WORKOS_CLIENT_ID,
    });

    // Store the session in a cookie
    setCookie(c, 'wos-session', sealedSession, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
    });

    // Use the information in `user` for further business logic.
    console.log('returning user and session', user, sealedSession);

    // Redirect the user to the homepage
    return c.redirect('http://localhost:4000');
  } catch (error) {
    return c.redirect('/login');
  }
});

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

app.get('/auth/get-customer', async (c) => {
  const db = c.env.DB;
  const workos = c.get('workos');
  const jwtPayload = c.get('jwtPayload');
  if (!jwtPayload?.sub) {
    return c.json({ err: 'No auth data' }, 400);
  }
  console.log('jwtPayload', jwtPayload);

  const userId = jwtPayload.sub;
  // const stripe = require('stripe')(c.env.STRIPE_SECRET_KEY);

	try {
		const orgMemberships = await workos.userManagement.listOrganizationMemberships({
			userId: userId,
		});
		const orgId = orgMemberships.data[0].organizationId; // each user is in only one org

    // TODO change this to KV
    const fbUserIdQuery = await db.prepare(
      `SELECT firebase_user_id FROM workos_user_lookup WHERE workos_user_id = '${userId}'`
    ).run();
    if (!fbUserIdQuery.success) {
      throw new Error('User ID not found');
    }
    const fbUserId = fbUserIdQuery.results[0].firebase_user_id;

    // Get document data from Firestore
    // const userRef = db.collection('users').doc(fbUserId);
    // const userDoc = await userRef.get();
    // if (!userDoc.exists) {
    //   console.log('No such document!');
    // } else {
    //   console.log('Document data:', userDoc.data());
    // }

		// const customers = await stripe.customers.search({
		// 	query: `metadata[\'organizationId\']:\'${orgId}\'`,
		// });

		// if (!customers.data?.length) {
		// 	throw new Error('Customer ID not found');
		// }
		// // we expect only one result
		// if (customers.data.length > 1) {
		// 	throw new Error('Too many user ID matches. Expected: 1');
		// }

		// return c.json({ id: customers.data[0].id });
    return c.json({ payload: jwtPayload, workOSOrgId: orgId, fbUserId });
	} catch (err) {
		return c.json({ err: `Error getting customer: ${err.message}` }, 500);
	}
});

// TODO cron job to consolidate D1 into KV

export default app;
