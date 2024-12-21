import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { html, Html } from '@elysiajs/html';

import { dbService, usersInsertSchema } from './db';

export const userService = new Elysia({ name: 'user/service' })
  .use(html())
  .use(dbService)
  .onStart(async ({ decorator: { db, schema } }) => {
    await db
      .insert(schema.users)
      .values({ username: 'admin', password: await Bun.password.hash('admin') })
      .onConflictDoNothing({ target: schema.users.username });
  })
  .use(
    jwt({
      name: 'clientJWT',
      secret: 'client JWT secret',
      schema: t.Object({ username: t.String() }),
    }),
  )
  .macro(({ onBeforeHandle }) => ({
    isSignIn(enabled: boolean) {
      if (!enabled) return;

      onBeforeHandle(
        async ({ headers: { authorization }, error, clientJWT }) => {
          if (!authorization) {
            return error(401, { success: false, message: 'Unauthorized' });
          }

          const payload = await clientJWT.verify(authorization);
          if (payload == false) {
            return error(401, { success: false, message: 'Unauthorized' });
          }
        },
      );
    },
  }));

const Layout = ({ children }: { children: any }) => (
  <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bulma@1.0.2/css/bulma.min.css"
      />
      <script
        src="https://unpkg.com/htmx.org@2.0.4"
        integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+"
        crossorigin="anonymous"
      ></script>
      <script src="/public/htmx-setup.js"></script>
    </head>
    <body>
      <div class="container">{children}</div>
    </body>
  </html>
);

const SignInForm = ({
  redirect,
  error,
  values,
}: {
  redirect?: string;
  error?: string;
  values?: { username: string; password: string };
}) => (
  <form
    hx-target="this"
    hx-swap="outerHTML"
    hx-post={redirect ? `/auth/signin?redirect=${redirect}` : '/auth/signin'}
    hx-push-url="true"
  >
    <div class="field">
      <label class="label">Username</label>
      <div class="control">
        <input
          type="text"
          class="input"
          name="username"
          placeholder="Username"
          value={values ? values.username : ''}
          required={true}
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Password</label>
      <div class="control">
        <input
          type="password"
          class="input"
          name="password"
          placeholder="Password"
          value={values ? values.password : ''}
          required={true}
        />
      </div>
    </div>

    {error && <div class="notification is-danger">{error}</div>}

    <button class="button is-link" type="submit">
      Signin
    </button>
  </form>
);

export const user = new Elysia()
  .use(userService)
  .get('/', async ({ clientJWT, cookie: { auth }, redirect }) => {
    const profile = await clientJWT.verify(auth.value);

    if (!profile) return redirect('/auth/signin?redirect=/');

    return (
      <Layout>
        <div class="section">
          <h3 class="title is-3 has-text-centered">
            Welcome {profile.username}
          </h3>
        </div>
      </Layout>
    );
  })
  .get(
    '/auth/signin',
    async ({
      query: { redirect: redirectUrl },
      redirect,
      cookie: { auth },
      clientJWT,
    }) => {
      const profile = await clientJWT.verify(auth.value);
      if (profile) return redirect(redirectUrl || '/');

      return (
        <Layout>
          <div class="section">
            <h3 class="title is-3 has-text-centered">Signin</h3>
            <SignInForm redirect={redirectUrl} />
          </div>
        </Layout>
      );
    },
    {
      query: t.Object({
        redirect: t.Optional(t.String()),
      }),
    },
  )
  .post(
    '/auth/signin',
    async ({
      body: { username, password },
      error,
      clientJWT,
      db,
      query: { redirect: redirectUrl },
      cookie: { auth },
      set,
    }) => {
      const user = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.username, username),
      });

      if (!user || !(await Bun.password.verify(password, user.password))) {
        return error(
          401,
          <SignInForm
            redirect={redirectUrl}
            error="Invalid Credentials"
            values={{ username, password }}
          />,
        );
      }

      const token = await clientJWT.sign({
        username,
      });

      auth.set({
        value: token,
        httpOnly: true,
      });

      set.headers['HX-Redirect'] = redirectUrl || '/';

      return;
    },
    {
      body: t.Pick(usersInsertSchema, ['username', 'password']),
      query: t.Object({ redirect: t.Optional(t.String()) }),
    },
  );
