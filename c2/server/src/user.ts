import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';

import { dbService, usersInsertSchema } from './db';

export const userService = new Elysia({ name: 'user/service' })
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

export const user = new Elysia().use(userService).post(
  '/auth/signin',
  async ({ body: { username, password }, error, clientJWT, db }) => {
    const user = await db.query.users.findFirst({
      where: (users, { eq }) => eq(users.username, username),
    });

    if (!user || !(await Bun.password.verify(password, user.password))) {
      return error(401, { success: false, message: 'Invalid credentials' });
    }

    const token = await clientJWT.sign({
      username,
    });

    return {
      success: true,
      message: 'Signin successful',
      token,
    };
  },
  {
    body: t.Pick(usersInsertSchema, ['username', 'password']),
  },
);
