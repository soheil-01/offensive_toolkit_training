import { sqliteTable, integer, text } from 'drizzle-orm/sqlite-core';
import { sql, relations } from 'drizzle-orm';

export const users = sqliteTable('users_table', {
  id: integer().primaryKey({ autoIncrement: true }),
  username: text().unique().notNull(),
  password: text().notNull(),
});

export const implants = sqliteTable('implants_table', {
  id: integer().primaryKey({ autoIncrement: true }),
  lastSeenAt: integer({ mode: 'timestamp' })
    .default(sql`(unixepoch())`)
    .notNull(),
});

export const implantsRelations = relations(implants, ({ many }) => ({
  commands: many(commands),
}));

export const commands = sqliteTable('commands_table', {
  id: integer().primaryKey({ autoIncrement: true }),
  implantId: integer()
    .references(() => implants.id, { onDelete: 'cascade' })
    .notNull(),
  type: text().notNull(),
  payload: text({ mode: 'json' }),
  status: text({
    enum: ['Queued', 'Executing', 'Completed', 'Failed'],
  })
    .default('Queued')
    .notNull(),
  response: text({ mode: 'json' }),
  createdAt: integer({ mode: 'timestamp' })
    .default(sql`(unixepoch())`)
    .notNull(),
});

export const commandsRelations = relations(commands, ({ one }) => ({
  implant: one(implants, {
    fields: [commands.implantId],
    references: [implants.id],
  }),
}));
