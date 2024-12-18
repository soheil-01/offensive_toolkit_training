PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_commands_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`implantId` integer NOT NULL,
	`type` text NOT NULL,
	`payload` text,
	`status` text DEFAULT 'Queued' NOT NULL,
	`response` text,
	`createdAt` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`implantId`) REFERENCES `implants_table`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_commands_table`("id", "implantId", "type", "payload", "status", "response", "createdAt") SELECT "id", "implantId", "type", "payload", "status", "response", "createdAt" FROM `commands_table`;--> statement-breakpoint
DROP TABLE `commands_table`;--> statement-breakpoint
ALTER TABLE `__new_commands_table` RENAME TO `commands_table`;--> statement-breakpoint
PRAGMA foreign_keys=ON;