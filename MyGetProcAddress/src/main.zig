const std = @import("std");
const win_utils = @import("win_utils.zig");

const win = std.os.windows;

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(win.WINAPI) win.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: win.HMODULE, lpProcName: [*:0]const u8) callconv(win.WINAPI) win.FARPROC;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const h_module1 = try win_utils.getModuleHandle(allocator, "ntdll.dll");
    const h_module2 = GetModuleHandleA("ntdll.dll");

    std.debug.print("getModuleHandle: 0x{x}\n", .{@intFromPtr(h_module1)});
    std.debug.print("GetModuleHandleA: 0x{x}\n", .{@intFromPtr(h_module2)});

    const proc1 = try win_utils.getProcAddress(h_module1, "NtProtectVirtualMemory");
    const proc2 = GetProcAddress(h_module2, "NtProtectVirtualMemory");

    std.debug.print("getProcAddress: 0x{x}\n", .{@intFromPtr(proc1)});
    std.debug.print("GetProcAddress: 0x{x}\n", .{@intFromPtr(proc2)});
}
