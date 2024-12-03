const std = @import("std");
const CoffLoader = @import("coff_loader.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingFilePath;

    var coff_loader = try CoffLoader.init(allocator, args[1]);
    defer coff_loader.deinit();

    try coff_loader.load();
}
