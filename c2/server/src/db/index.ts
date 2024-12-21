import { drizzle } from 'drizzle-orm/bun-sqlite';
import { Elysia } from 'elysia';
import { createInsertSchema } from 'drizzle-typebox';

import * as schema from './schema';

export const usersInsertSchema = createInsertSchema(schema.users);
export const commandsInsertSchema = createInsertSchema(schema.commands);

export const dbService = new Elysia({ name: 'db/service' })
  .decorate({
    db: drizzle(process.env.DB_FILE_NAME!, { schema }),
    schema,
  })
  .as('plugin');
