const std = @import("std");
const Disassembler = @import("dis_x86_64").Disassembler;
const win = std.os.windows;

const GetModuleHandleW = win.kernel32.GetModuleHandleW;
const GetProcAddress = win.kernel32.GetProcAddress;

pub fn main() !void {
    const h_ntdll = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("ntdll.dll")) orelse return error.FailedToLoadNtdll;
    const nt_allocate_virtual_memory = GetProcAddress(h_ntdll, "NtAllocateVirtualMemory") orelse return error.FailedToLoadNtAllocateVirtualMemory;

    const proc = try resolveJmpTarget(try resolveJmpTarget(@ptrCast(nt_allocate_virtual_memory)));

    var proc_bytes: [300]u8 = undefined;
    @memcpy(&proc_bytes, proc);

    var disassembler = Disassembler.init(&proc_bytes);

    while (try disassembler.next()) |inst| {
        if (inst.encoding.mnemonic == .mov and inst.ops[0] == .reg and inst.ops[0].reg == .rax) {
            std.debug.print("Found mov rax,... \n", .{});
        }
    }
}

fn resolveJmpTarget(addr: [*]const u8) ![*]const u8 {
    var bytes: [10]u8 = undefined;
    @memcpy(&bytes, addr);

    var disassembler = Disassembler.init(&bytes);

    const first_inst = try disassembler.next() orelse return error.InstuctionNotFound;
    if (first_inst.encoding.mnemonic != .jmp) return error.NotAJmp;

    const first_op = first_inst.ops[0];

    switch (first_op) {
        .imm => |imm| {
            const relative_offset = imm.signed;
            const base_address: isize = @intCast(@intFromPtr(addr));
            return @ptrFromInt(@as(usize, @intCast(base_address + 5 + relative_offset)));
        },
        .mem => |mem| {
            if (mem != .m_rip) return error.InvalidOp;
            const rip: [*]const u8 = @ptrFromInt(@intFromPtr(addr) + 6);

            var rip_bytes: [6]u8 = undefined;
            @memcpy(&rip_bytes, rip);

            return @ptrFromInt(std.mem.readInt(u48, &rip_bytes, .little));
        },
        else => return error.InvalidOp,
    }
}
