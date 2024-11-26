const std = @import("std");
const root = @import("root.zig");

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.C) *opaque {};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const h_module1 = try root.getModuleHandle(allocator, "ntdll.dll");
    const h_module2 = GetModuleHandleA("ntdll.dll");

    std.debug.print("getModuleHandle: 0x{x}\n", .{@intFromPtr(h_module1)});
    std.debug.print("GetModuleHandleA: 0x{x}\n", .{@intFromPtr(h_module2)});
}
