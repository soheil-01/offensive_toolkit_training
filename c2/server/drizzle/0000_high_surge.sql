CREATE TABLE `commands_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`implantId` integer NOT NULL,
	`type` text NOT NULL,
	`payload` text,
	`status` text NOT NULL,
	`response` text,
	`createdAt` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`implantId`) REFERENCES `implants_table`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `implants_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`lastSeenAt` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `users_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`passwrod` text NOT NULL
);
