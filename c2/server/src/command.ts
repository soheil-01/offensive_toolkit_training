import { Elysia, t } from 'elysia';
import { implantService } from './implant';

import { userService } from './user';
import { dbService, commandsInsertSchema } from './db';

export const command = new Elysia({ prefix: '/commands' })
  .use(userService)
  .use(implantService)
  .use(dbService)
  .get(
    '/',
    async ({ db }) => {
      const commands = await db.query.commands.findMany();
      return commands;
    },
    {
      isSignIn: true,
    },
  )
  .get(
    '/:id',
    async ({ params: { id }, error, db }) => {
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
    '/',
    async ({ error, body: { implantId, type, payload }, db, schema }) => {
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
    '/:id/status',
    async ({
      params: { id: commandId },
      headers: { authorization },
      body: { status, response },
      implantJWT,
      error,
      db,
      schema,
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
  );
