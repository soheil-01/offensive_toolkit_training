import { Elysia } from 'elysia';
import { swagger } from '@elysiajs/swagger';
import { staticPlugin } from '@elysiajs/static';

import { user } from './user';
import { implant } from './implant';
import { command } from './command';

const app = new Elysia()
  .use(staticPlugin())
  .use(swagger())
  .use(user)
  .use(implant)
  .use(command)
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
