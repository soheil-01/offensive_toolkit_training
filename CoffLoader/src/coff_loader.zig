const std = @import("std");

const win = std.os.windows;

const CoffHeader = std.coff.CoffHeader;
const SectionHeader = std.coff.SectionHeader;
const Relocation = extern struct {
    virtual_address: u32 align(1),
    symbol_table_index: u32 align(1),
    type: u16 align(1),
};
const SectionNumber = std.coff.SectionNumber;
const SymType = std.coff.SymType;
const StorageClass = std.coff.StorageClass;
const Symbol = extern struct {
    name: [8]u8 align(1),
    value: u32 align(1),
    section_number: SectionNumber align(1),
    type: SymType align(1),
    storage_class: StorageClass align(1),
    number_of_aux_symbols: u8 align(1),

    fn getNameOffset(self: Symbol) ?u32 {
        if (!std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) return null;
        const offset = std.mem.readInt(u32, self.name[4..8], .little);
        return offset;
    }

    fn getName(self: *const Symbol, coff_loader: *const CoffLoader) []const u8 {
        if (!std.mem.eql(u8, self.name[0..4], "\x00\x00\x00\x00")) {
            const len = std.mem.indexOfScalar(u8, &self.name, @as(u8, 0)) orelse self.name.len;
            return self.name[0..len];
        }

        const name_offset = self.getNameOffset().?;
        const string_table_offset = coff_loader.coff_file.ptr + coff_loader.coff_header.pointer_to_symbol_table + @sizeOf(Symbol) * coff_loader.coff_header.number_of_symbols;
        const name_ptr: [*:0]u8 = @ptrCast(string_table_offset + name_offset);
        const name_len = std.mem.indexOfSentinel(u8, 0, name_ptr);

        return name_ptr[0..name_len];
    }

    pub fn getOffset(self: Symbol, comptime T: type, symbol_ref_address: [*]u8) T {
        switch (T) {
            u32, u64 => {},
            else => @compileError("Unsupported type for symbol offset calculation"),
        }

        if ((self.storage_class == .STATIC and self.value != 0) or (self.storage_class == .EXTERNAL and self.section_number != .UNDEFINED)) {
            return self.value;
        }

        return std.mem.readInt(T, symbol_ref_address[0..@sizeOf(T)], .little);
    }
};
const ImageRelAmd64 = std.coff.ImageRelAmd64;

extern "kernel32" fn LoadLibraryA(lpModuleName: ?[*:0]const u8) callconv(win.WINAPI) win.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: win.HMODULE, lpProcName: [*:0]const u8) callconv(win.WINAPI) win.FARPROC;

const CoffLoader = @This();

allocator: std.mem.Allocator,
coff_file: []u8,
coff_header: *CoffHeader,
section_address_memory: []?[*]u8,
got: std.ArrayList(u8),
bss: std.ArrayList(u8),

pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !CoffLoader {
    const coff_file = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
    const coff_header: *CoffHeader = @alignCast(@ptrCast(coff_file.ptr));

    const section_address_memory = try allocator.alloc(?[*]u8, coff_header.number_of_sections);
    @memset(section_address_memory, null);

    return CoffLoader{
        .allocator = allocator,
        .coff_file = coff_file,
        .coff_header = coff_header,
        .section_address_memory = section_address_memory,
        .got = std.ArrayList(u8).init(allocator),
        .bss = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(self: CoffLoader) void {
    for (self.section_address_memory) |section| if (section != null) win.VirtualFree(section.?, 0, win.MEM_RELEASE);
    self.allocator.free(self.section_address_memory);
    self.allocator.free(self.coff_file);
    self.got.deinit();
    self.bss.deinit();
}

fn loadSectionsIntoMemory(self: *CoffLoader) !void {
    for (0..self.coff_header.number_of_sections) |i| {
        const section_header: *SectionHeader = @alignCast(@ptrCast(self.coff_file.ptr + @sizeOf(CoffHeader) + i * @sizeOf(SectionHeader)));

        if (section_header.size_of_raw_data == 0) continue;

        const is_text_section = std.mem.eql(u8, section_header.name[0..5], ".text");

        const section_data: [*]u8 = @ptrCast(try win.VirtualAlloc(
            null,
            section_header.size_of_raw_data,
            win.MEM_COMMIT | win.MEM_RESERVE | win.MEM_TOP_DOWN,
            if (is_text_section) win.PAGE_EXECUTE_READWRITE else win.PAGE_READWRITE,
        ));

        @memcpy(section_data, self.coff_file[section_header.pointer_to_raw_data .. section_header.pointer_to_raw_data + section_header.size_of_raw_data]);

        self.section_address_memory[i] = section_data;
    }
}

fn performRelocations(self: *CoffLoader) !void {
    for (0..self.coff_header.number_of_sections) |i| {
        const section_header: *SectionHeader = @alignCast(@ptrCast(self.coff_file.ptr + @sizeOf(CoffHeader) + i * @sizeOf(SectionHeader)));

        for (0..section_header.number_of_relocations) |j| {
            const relocation: *Relocation = @ptrCast(self.coff_file.ptr + section_header.pointer_to_relocations + j * @sizeOf(Relocation));
            const symbol: *Symbol = @ptrCast(self.coff_file.ptr + self.coff_header.pointer_to_symbol_table + relocation.symbol_table_index * @sizeOf(Symbol));

            const section_data = self.section_address_memory[i] orelse return error.SectionIsEmpty;
            const symbol_name = symbol.getName(self);
            const symbol_ref_address = section_data + relocation.virtual_address;

            var bss_address: ?*anyopaque = null;

            // Process functions and uninitialized variables
            if (symbol.storage_class == .EXTERNAL and symbol.section_number == .UNDEFINED) {
                const function_address = try self.loadExternalFunction(symbol_name);
                if (function_address != null and relocation.type == @intFromEnum(ImageRelAmd64.rel32)) {
                    const relative_address: u32 = @intCast(@intFromPtr(function_address.?) - (@intFromPtr(symbol_ref_address) + 4));
                    @memcpy(symbol_ref_address, std.mem.asBytes(&relative_address));
                    continue;
                } else {
                    const bss_offset = self.bss.items.len;
                    try self.bss.appendNTimes(0, symbol.value);
                    bss_address = &self.bss.items[bss_offset];
                }
            }

            switch (@as(ImageRelAmd64, @enumFromInt(relocation.type))) {
                .addr64 => {
                    var symbol_def_address: u64 = 0;

                    if (bss_address != null) {
                        symbol_def_address = @intFromPtr(bss_address.?) - (@intFromPtr(symbol_ref_address) + 4);
                    } else {
                        const symbol_offset = symbol.getOffset(u64, symbol_ref_address);
                        symbol_def_address = symbol_offset + @intFromPtr(self.section_address_memory[@intFromEnum(symbol.section_number) - 1]);
                    }

                    @memcpy(symbol_ref_address, std.mem.asBytes(&symbol_def_address));
                },
                .addr32nb => {
                    var symbol_def_address: u32 = 0;
                    if (bss_address != null) {
                        symbol_def_address = @intCast(@intFromPtr(bss_address.?) - (@intFromPtr(symbol_ref_address) + 4));
                    } else {
                        const symbol_offset = symbol.getOffset(u32, symbol_ref_address);

                        symbol_def_address = @intCast(@intFromPtr(self.section_address_memory[@intFromEnum(symbol.section_number) - 1]) - (@intFromPtr(symbol_ref_address) + 4));

                        if (@as(u64, symbol_def_address) + @as(u64, symbol_offset) > std.math.maxInt(u32)) {
                            std.debug.print("Warning: Relocation overflow detected. Skipping this relocation.\n", .{});
                            continue;
                        }

                        symbol_def_address += symbol_offset;

                        @memcpy(symbol_ref_address, std.mem.asBytes(&symbol_def_address));
                    }
                },
                .rel32, .rel32_1, .rel32_2, .rel32_3, .rel32_4, .rel32_5 => {
                    var symbol_def_address: u32 = 0;
                    if (bss_address != null) {
                        symbol_def_address = @intCast(@intFromPtr(bss_address.?) - (relocation.type - 4) - (@intFromPtr(symbol_ref_address) + 4));
                    } else {
                        const symbol_offset = symbol.getOffset(u32, symbol_ref_address);
                        symbol_def_address = @intCast(@intFromPtr(self.section_address_memory[@intFromEnum(symbol.section_number) - 1]) - (relocation.type - 4) - (@intFromPtr(symbol_ref_address) + 4));

                        if (@as(u64, symbol_def_address) + @as(u64, symbol_offset) > std.math.maxInt(u32)) {
                            std.debug.print("Warning: Relocation overflow detected. Skipping this relocation.\n", .{});
                            continue;
                        }

                        symbol_def_address += symbol_offset;

                        @memcpy(symbol_ref_address, std.mem.asBytes(&symbol_def_address));
                    }
                },
                else => return error.UnsupportedRelocationType,
            }
        }
    }
}

fn loadExternalFunction(self: *CoffLoader, symbol_name: []const u8) !?*anyopaque {
    if (!std.mem.startsWith(u8, symbol_name, "__imp_")) return null;

    var parts = std.mem.split(u8, symbol_name[6..], "$");
    const module_name = parts.first();
    const proc_name = parts.next().?;

    const module_name_z = try self.allocator.dupeZ(u8, module_name);
    defer self.allocator.free(module_name_z);
    const proc_name_z = try self.allocator.dupeZ(u8, proc_name);
    defer self.allocator.free(proc_name_z);

    const function_address = GetProcAddress(LoadLibraryA(module_name_z), proc_name_z);

    const got_offset = self.got.items.len;
    try self.got.appendSlice(std.mem.asBytes(&function_address));
    const entry_address = &self.got.items[got_offset];

    return entry_address;
}

fn executeCoffCode(self: *CoffLoader) !void {
    for (0..self.coff_header.number_of_symbols) |i| {
        const symbol: *Symbol = @ptrCast(self.coff_file.ptr + self.coff_header.pointer_to_symbol_table + i * @sizeOf(Symbol));
        const symbol_name = symbol.getName(self);

        if (std.mem.eql(u8, symbol_name, "go")) {
            const function: *fn () void = @ptrCast(self.section_address_memory[@intFromEnum(symbol.section_number) - 1].? + symbol.value);
            function();
        }
    }
}

pub fn load(self: *CoffLoader) !void {
    try self.loadSectionsIntoMemory();
    try self.performRelocations();
    try self.executeCoffCode();
}