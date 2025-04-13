const std = @import("std");
const c = @cImport({
    @cInclude("capstone/capstone.h");
});
const win = std.os.windows;

const NtProtectVirtualMemoryFn = *const fn (processHandle: win.HANDLE, baseAddress: win.LPVOID, regionSize: *win.SIZE_T, newProtection: u32, oldProtection: *u32) callconv(win.WINAPI) win.NTSTATUS;

const MEMORY_BASIC_INFORMATION = win.MEMORY_BASIC_INFORMATION;

const GetModuleHandleW = win.kernel32.GetModuleHandleW;
const GetProcAddress = win.kernel32.GetProcAddress;
const VirtualQuery = win.kernel32.VirtualQuery;

pub fn main() !void {
    const h_ntdll = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("ntdll.dll")) orelse return error.FailedToLoadNtdll;
    const nt_protect_virtual_memory = GetProcAddress(h_ntdll, "NtProtectVirtualMemory") orelse return error.FailedToLoadNtProtectVirtualMemory;
    const nt_allocate_virtual_memory = GetProcAddress(h_ntdll, "NtAllocateVirtualMemory") orelse return error.FailedToLoadNtAllocateVirtualMemory;

    const NtProtectVirtualMemory: NtProtectVirtualMemoryFn = @ptrCast(try findOriginalSyscall(@ptrCast(nt_protect_virtual_memory)));

    try unhook(@ptrCast(nt_allocate_virtual_memory), NtProtectVirtualMemory);

    std.debug.print("[!] NtAllocateVirtualMemory unhooked!\n", .{});
    std.debug.print("[!] press any key to call NtAllocateVirtualMemory...\n", .{});
    _ = try std.io.getStdIn().reader().readByte();

    const base_address = try win.VirtualAlloc(
        null,
        1024,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_READWRITE,
    );

    defer win.VirtualFree(
        base_address,
        0,
        win.MEM_RELEASE,
    );
}

fn unhook(addr: [*]u8, NtProtectVirtualMemory: NtProtectVirtualMemoryFn) !void {
    const process_handle = win.GetCurrentProcess();

    const original_syscall = try findOriginalSyscall(addr);
    const unhooked_bytes = generateJumpBytes(@intFromPtr(addr), @intFromPtr(original_syscall));

    var region_size: usize = 20;
    var old_protect: u32 = undefined;

    var result = NtProtectVirtualMemory(
        process_handle,
        @constCast(@ptrCast(&addr)),
        &region_size,
        win.PAGE_EXECUTE_READWRITE,
        &old_protect,
    );

    if (result != .SUCCESS) {
        return error.NtProtectVirtualMemoryFailed;
    }

    @memcpy(addr, &unhooked_bytes);

    result = NtProtectVirtualMemory(
        process_handle,
        @constCast(@ptrCast(&addr)),
        &region_size,
        old_protect,
        &old_protect,
    );

    if (result != .SUCCESS) {
        return error.NtProtectVirtualMemoryFailed;
    }
}

fn findOriginalSyscall(addr: [*]const u8) ![*]const u8 {
    const proc = try resolveJmpTarget(try resolveJmpTarget(addr));

    var handle: c.csh = undefined;
    defer _ = c.cs_close(&handle);

    var instructions: [*c]c.cs_insn = undefined;

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle) != c.CS_ERR_OK) {
        return error.FailedToOpenCapstone;
    }

    _ = c.cs_option(handle, c.CS_OPT_DETAIL, c.CS_OPT_ON);

    const count = c.cs_disasm(
        handle,
        proc,
        2000,
        @intFromPtr(proc),
        0,
        &instructions,
    );

    if (count > 0) {
        for (instructions[0..count]) |inst| {
            if (inst.id == c.X86_INS_MOV) {
                const first_operand = inst.detail.?.*.unnamed_0.x86.operands[0];
                const second_operand = inst.detail.?.*.unnamed_0.x86.operands[1];

                if (first_operand.type == c.X86_OP_REG and
                    first_operand.unnamed_0.reg == c.X86_REG_RAX and
                    second_operand.type == c.X86_OP_MEM and
                    second_operand.unnamed_0.mem.base == c.X86_REG_RIP)
                {
                    const next_inst_addr = inst.address + inst.size;
                    const disp: u64 = @intCast(second_operand.unnamed_0.mem.disp);

                    const source: [*]const u8 = @ptrFromInt(next_inst_addr + disp);
                    const source_value = std.mem.readInt(usize, source[0..@sizeOf(usize)], .little);

                    const is_readable = isAddressReadable(@ptrFromInt(source_value));
                    if (is_readable) {
                        const syscall_pattern_detected = try detectSyscallPattern(@ptrFromInt(source_value));

                        if (syscall_pattern_detected) {
                            return @ptrFromInt(source_value);
                        }
                    }
                }
            }
        }

        defer c.cs_free(instructions, count);
    }

    return error.FailedToUnhookSyscall;
}

fn generateJumpBytes(addr: usize, target_addr: usize) [5]u8 {
    const signed_target_adr: isize = @intCast(target_addr);
    const rip: isize = @intCast(addr + 5);

    const relative_address: i32 = @intCast(signed_target_adr - rip);

    var bytes: [5]u8 = undefined;
    bytes[0] = 0xe9;

    std.mem.writeInt(i32, bytes[1..5], relative_address, .little);

    return bytes;
}

fn resolveJmpTarget(addr: [*]const u8) ![*]const u8 {
    var handle: c.csh = undefined;
    defer _ = c.cs_close(&handle);

    var instructions: [*c]c.cs_insn = undefined;

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle) != c.CS_ERR_OK) {
        return error.FailedToOpenCapstone;
    }

    _ = c.cs_option(handle, c.CS_OPT_DETAIL, c.CS_OPT_ON);

    const count = c.cs_disasm(
        handle,
        addr,
        20,
        @intFromPtr(addr),
        0,
        &instructions,
    );

    if (count > 0) {
        const first_inst = instructions[0];

        if (first_inst.id != c.X86_INS_JMP) {
            return error.NotAJmp;
        }

        const first_operand = first_inst.detail.?.*.unnamed_0.x86.operands[0];

        switch (first_operand.type) {
            c.X86_OP_IMM => {
                return @ptrFromInt(@as(usize, @intCast(first_operand.unnamed_0.imm)));
            },
            c.X86_OP_MEM => {
                if (first_operand.unnamed_0.mem.base == c.X86_REG_RIP) {
                    const next_inst = instructions[1];
                    const target_addr = std.mem.readInt(usize, next_inst.bytes[0..@sizeOf(usize)], .little);
                    return @ptrFromInt(target_addr);
                }
                return error.InvalidOp;
            },
            else => return error.InvalidOp,
        }

        defer c.cs_free(instructions, count);
    }

    return error.FailedToResolveJmpTarget;
}

fn detectSyscallPattern(addr: [*]const u8) !bool {
    var handle: c.csh = undefined;
    defer _ = c.cs_close(&handle);

    var instructions: [*c]c.cs_insn = undefined;

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle) != c.CS_ERR_OK) {
        return error.FailedToOpenCapstone;
    }

    _ = c.cs_option(handle, c.CS_OPT_DETAIL, c.CS_OPT_ON);

    const count = c.cs_disasm(
        handle,
        addr,
        20,
        @intFromPtr(addr),
        0,
        &instructions,
    );

    if (count > 0) {
        defer c.cs_free(instructions, count);

        const first_inst = instructions[0];
        const first_inst_operand0 = first_inst.detail.?.*.unnamed_0.x86.operands[0];
        const first_inst_operand1 = first_inst.detail.?.*.unnamed_0.x86.operands[1];

        const second_inst = instructions[1];
        const second_inst_operand0 = second_inst.detail.?.*.unnamed_0.x86.operands[0];

        return first_inst.id == c.X86_INS_MOV and
            first_inst_operand0.type == c.X86_OP_REG and
            first_inst_operand0.unnamed_0.reg == c.X86_REG_R10 and
            first_inst_operand1.type == c.X86_OP_REG and
            first_inst_operand1.unnamed_0.reg == c.X86_REG_RCX and
            second_inst.id == c.X86_INS_MOV and
            second_inst_operand0.type == c.X86_OP_REG and
            second_inst_operand0.unnamed_0.reg == c.X86_REG_EAX;
    }

    return false;
}

fn isAddressReadable(addr: ?win.LPVOID) bool {
    var meminfo: MEMORY_BASIC_INFORMATION = undefined;

    const result = VirtualQuery(
        addr,
        &meminfo,
        @sizeOf(MEMORY_BASIC_INFORMATION),
    );

    if (result == 0) {
        return false;
    }

    return meminfo.State == win.MEM_COMMIT and (meminfo.Protect & win.PAGE_NOACCESS) == 0;
}
