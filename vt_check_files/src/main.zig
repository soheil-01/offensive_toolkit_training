const std = @import("std");
const http = std.http;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn hash_file(file_path: []const u8) ![Sha256.digest_length]u8 {
    const file = try std.fs.cwd().openFile(file_path, .{});
    const reader = file.reader();

    var sha256 = Sha256.init(.{});

    var buf: [1024]u8 = undefined;
    var n = try reader.read(&buf);

    while (n != 0) {
        sha256.update(buf[0..n]);
        n = try reader.read(&buf);
    }

    return sha256.finalResult();
}

fn fileExistsOnVirusTotal(allocator: std.mem.Allocator, client: *http.Client, vt_api_key: []const u8, file_hash: [Sha256.digest_length]u8) !bool {
    const url = "https://www.virustotal.com/api/v3/files/" ++ std.fmt.bytesToHex(file_hash, .lower);
    const uri = try std.Uri.parse(url);

    const server_header_buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(server_header_buffer);

    var req = try client.open(.GET, uri, .{
        .server_header_buffer = server_header_buffer,
        .extra_headers = &.{
            .{
                .name = "x-apikey",
                .value = vt_api_key,
            },
        },
    });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    return switch (req.response.status) {
        .ok => true,
        .not_found => false,
        else => return error.UnexpectedVirusTotalResponse,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingDir;

    const dir = args[1];

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    const vt_api_key = env_map.get("VT_API_KEY") orelse return error.MissingVTAPIKey;

    var client = http.Client{
        .allocator = allocator,
    };
    defer client.deinit();

    var iter_dir = try std.fs.cwd().openDir(dir, .{ .iterate = true });
    defer iter_dir.close();

    var walker = try iter_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;

        const file_full_path = try std.fs.path.join(allocator, &.{ dir, entry.path });
        defer allocator.free(file_full_path);

        const file_hash = try hash_file(file_full_path);

        if (try fileExistsOnVirusTotal(allocator, &client, vt_api_key, file_hash)) {
            std.debug.print("[!]Warning: '{s}' has been found on VirusTotal\n", .{file_full_path});
        }
    }
}
