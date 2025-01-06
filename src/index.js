import { Hono } from "hono";
import { env } from 'hono/adapter'
import { getConnInfo } from 'hono/cloudflare-workers'
import { bearerAuth } from 'hono/bearer-auth'
import { cors } from 'hono/cors'
import { HTTPException } from 'hono/http-exception'
import { setCookie } from 'hono/cookie';
import { zValidator } from '@hono/zod-validator'
import { WorkOS } from '@workos-inc/node';
import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
import * as Firestore from 'fireworkers';

import { createCustomToken } from './utils';
import { firebaseOrgCreate, firebaseUserCreate } from './schemas';

async function createDb(SERVICE_ACCOUNT_JSON) {
  return Firestore.init(JSON.parse(SERVICE_ACCOUNT_JSON));
}

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
        return false;
      }
      c.set('jwtPayload', res.payload);
      return true;
    },
  })
)

app.use(
  '/firebase/*',
  bearerAuth({
    verifyToken: async (token, c) => {
      const FIREBASE_SHARED_SECRET = env(c);
      if (token !== FIREBASE_SHARED_SECRET) {
        return false;
      }
      return true;
    },
  })
);

app.post('/firebase/create-workos-org', zValidator('json', firebaseOrgCreate), async (c) => {
  const { orgName, firebaseOrgId, createdByUserId, role } = c.req.valid('json');
  const workos = c.get('workos');

  // TODO need to make sure we've been given a valid firebase org id, org name, user who created it

  //go and create the org in WorkOS
  try {
    const workosOrg = await workos.organizations.createOrganization({
      name: orgName,
    });

    await workos.userManagement.createOrganizationMembership({
      organizationId: workosOrg.id,
      userId: createdByUserId,
      roleSlug: role,
    });

    // go and add the firebase orgId and the workos orgId to the d1 database
    const db = c.env.DB; // DB is the binding name for your D1 database
    await db
      .prepare(`INSERT INTO workos_organisation_lookup (workos_organisation_id, firestore_org_id) VALUES (?, ?) ON CONFLICT(workos_organisation_id) DO UPDATE SET firebase_org_id = '${firebaseOrgId}'`)
      .bind(workosOrg.id, firebaseOrgId)
      .run();

    return c.json({ success: true }, 201);
  } catch (err) {
		return c.json({ err: `Error creating organisation: ${err.message}` }, 500);
  }
});

// The user is created by authkit-react, but we need an endpoint to create the firestore doc
// Gets called by the WorkOS webhook on the user.created event.
// app.post('/firebase/create-user', zValidator('json', firebaseUserCreate), async (c) => { // FIXME parse correctly in zod
app.post('/create-firebase-user-doc', async (c) => {
  const workos = c.get('workos');
  const { SERVICE_ACCOUNT_JSON, WORKOS_WEBHOOK_SECRET } = env(c);

  const firestoreDb = await createDb(SERVICE_ACCOUNT_JSON);

  try {
    const payload = await c.req.json();

		// verify signature and construct event
		const sigHeader = c.req.header('workos-signature');
		const verified = await workos.webhooks.constructEvent({
			payload: payload,
			sigHeader: sigHeader,
			secret: WORKOS_WEBHOOK_SECRET,
    });
    const user = verified.data;

    //go and make the user in the firebase project
    await Firestore.set(
      firestoreDb,
      `users/${user.id}`,
      {
        apiKey: null, //this currently gets inserted by a firebase
        enabled: true,
      },
      { merge: true },
    );

    const db = c.env.DB; // DB is the binding name for your D1 database
    await db
      .prepare(`INSERT INTO workos_user_lookup (workos_user_id, firebase_user_id) VALUES (?, ?) ON CONFLICT(workos_user_id) DO UPDATE SET firebase_user_id = '${user.id}'`)
      .bind(user.id, user.id)
      .run();

    return c.json({ success: true }, 201);
  } catch (err) {
    console.error(err.message);
		return c.json({ err: `Error creating user: ${err.message}` }, 500);
  }
});

// TODO we create the user with authkit-react, but we need an endpoint to create the firestore doc
app.post("/create-account", async (c) => {
  const data = await c.req.json();
  const workos = c.get('workos');
  const info = getConnInfo(c);
  const { WORKOS_CLIENT_ID, SERVICE_ACCOUNT_JSON } = env(c);

  //make sure we have a password
  if (!data.password) {
    throw new HTTPException(400, 'Password is required')
  }

  if (!data.email) {
    throw new HTTPException(400, 'Email is required')
  }

  const firestoreDb = createDb(SERVICE_ACCOUNT_JSON)

  try {
    const userData = await workos.userManagement.createUser({
      email: data.email,
      password: data.password,
    });

    //go and make the user in the firebase project
    await Firestore.set(
      firestoreDb,
      `users/${userData.id}`,
      {
        apiKey: null, //this currently gets inserted by a firebase
        enabled: true
      },
      { merge: true }
    );

    const db = c.env.DB; // DB is the binding name for your D1 database
    await db
      .prepare(`INSERT INTO workos_user_lookup SET workos_user_id = ?, firebase_user_id = ?`)
      .bind(user.id, user.id)
      .run();

    const { user, accessToken, refreshToken } = await workos.userManagement.authenticateWithPassword({
      clientId: WORKOS_CLIENT_ID,
      email: data.email,
      password: data.password,
      ipAddress: info.remote.address,
      userAgent: c.req.header('User-Agent'),
    });

    const decoded = decodeJwt(accessToken);

    const idToken = await createCustomToken(JSON.parse(SERVICE_ACCOUNT_JSON), userData.id, {
      // orgId: orgData.results[0].firestore_org_id, //we dont have a org yet
      roles: [decoded.role]
    })

    return c.json({
      access_token: accessToken,
      id_token: accessToken,
      refresh_token: refreshToken,
      firebase_token: idToken,
    });

  } catch (err) {
    console.error(err.message);
		return c.json({ err: `Error creating user: ${err.message}` }, 500);
  }
});

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

// FIXME we shouldn't need this because firestore reading will be done on FE
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
