const std = @import("std");
const win = std.os.windows;

const HMODULE = win.HMODULE;
const FARPROC = win.FARPROC;
const LDR_DATA_TABLE_ENTRY = win.LDR_DATA_TABLE_ENTRY;
const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16 align(2),
    e_cblp: u16 align(2),
    e_cp: u16 align(2),
    e_crlc: u16 align(2),
    e_cparhdr: u16 align(2),
    e_minalloc: u16 align(2),
    e_maxalloc: u16 align(2),
    e_ss: u16 align(2),
    e_sp: u16 align(2),
    e_csum: u16 align(2),
    e_ip: u16 align(2),
    e_cs: u16 align(2),
    e_lfarlc: u16 align(2),
    e_ovno: u16 align(2),
    e_res: [4]u16 align(2),
    e_oemid: u16 align(2),
    e_oeminfo: u16 align(2),
    e_res2: [10]u16 align(2),
    e_lfanew: i32 align(2),
};
const IMAGE_FILE_MACHINE = enum(u16) {
    AXP64 = 644,
    I386 = 332,
    IA64 = 512,
    AMD64 = 34404,
    UNKNOWN = 0,
    TARGET_HOST = 1,
    R3000 = 354,
    R4000 = 358,
    R10000 = 360,
    WCEMIPSV2 = 361,
    ALPHA = 388,
    SH3 = 418,
    SH3DSP = 419,
    SH3E = 420,
    SH4 = 422,
    SH5 = 424,
    ARM = 448,
    THUMB = 450,
    ARMNT = 452,
    AM33 = 467,
    POWERPC = 496,
    POWERPCFP = 497,
    MIPS16 = 614,
    // ALPHA64 = 644, this enum value conflicts with AXP64
    MIPSFPU = 870,
    MIPSFPU16 = 1126,
    TRICORE = 1312,
    CEF = 3311,
    EBC = 3772,
    M32R = 36929,
    ARM64 = 43620,
    CEE = 49390,
};
const IMAGE_FILE_CHARACTERISTICS = packed struct(u16) {
    RELOCS_STRIPPED: u1 = 0,
    EXECUTABLE_IMAGE: u1 = 0,
    LINE_NUMS_STRIPPED: u1 = 0,
    LOCAL_SYMS_STRIPPED: u1 = 0,
    AGGRESIVE_WS_TRIM: u1 = 0,
    LARGE_ADDRESS_AWARE: u1 = 0,
    _6: u1 = 0,
    BYTES_REVERSED_LO: u1 = 0,
    @"32BIT_MACHINE": u1 = 0,
    DEBUG_STRIPPED: u1 = 0,
    REMOVABLE_RUN_FROM_SWAP: u1 = 0,
    NET_RUN_FROM_SWAP: u1 = 0,
    SYSTEM: u1 = 0,
    DLL: u1 = 0,
    UP_SYSTEM_ONLY: u1 = 0,
    BYTES_REVERSED_HI: u1 = 0,
};
const IMAGE_FILE_HEADER = extern struct {
    Machine: IMAGE_FILE_MACHINE,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: IMAGE_FILE_CHARACTERISTICS,
};
const IMAGE_OPTIONAL_HEADER_MAGIC = enum(u16) {
    NT_OPTIONAL_HDR_MAGIC = 523,
    NT_OPTIONAL_HDR32_MAGIC = 267,
    // NT_OPTIONAL_HDR64_MAGIC = 523, this enum value conflicts with NT_OPTIONAL_HDR_MAGIC
    ROM_OPTIONAL_HDR_MAGIC = 263,
};
const IMAGE_SUBSYSTEM = enum(u16) {
    UNKNOWN = 0,
    NATIVE = 1,
    WINDOWS_GUI = 2,
    WINDOWS_CUI = 3,
    OS2_CUI = 5,
    POSIX_CUI = 7,
    NATIVE_WINDOWS = 8,
    WINDOWS_CE_GUI = 9,
    EFI_APPLICATION = 10,
    EFI_BOOT_SERVICE_DRIVER = 11,
    EFI_RUNTIME_DRIVER = 12,
    EFI_ROM = 13,
    XBOX = 14,
    WINDOWS_BOOT_APPLICATION = 16,
    XBOX_CODE_CATALOG = 17,
};
const IMAGE_DLL_CHARACTERISTICS = packed struct(u16) {
    EX_CET_COMPAT: u1 = 0,
    EX_CET_COMPAT_STRICT_MODE: u1 = 0,
    EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: u1 = 0,
    EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC: u1 = 0,
    EX_CET_RESERVED_1: u1 = 0,
    HIGH_ENTROPY_VA: u1 = 0,
    DYNAMIC_BASE: u1 = 0,
    FORCE_INTEGRITY: u1 = 0,
    NX_COMPAT: u1 = 0,
    NO_ISOLATION: u1 = 0,
    NO_SEH: u1 = 0,
    NO_BIND: u1 = 0,
    APPCONTAINER: u1 = 0,
    WDM_DRIVER: u1 = 0,
    GUARD_CF: u1 = 0,
    TERMINAL_SERVER_AWARE: u1 = 0,
    // EX_CET_RESERVED_2 (bit index 5) conflicts with HIGH_ENTROPY_VA
};
const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};
const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    /// Deprecated
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};
const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    /// Deprecated
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
const IMAGE_NT_HEADERS32 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};
const IMAGE_NT_HEADERS = union(enum) {
    nt32: *IMAGE_NT_HEADERS32,
    nt64: *IMAGE_NT_HEADERS64,
};
const IMAGE_DIRECTORY_ENTRY = enum(u32) {
    ARCHITECTURE = 7,
    BASERELOC = 5,
    BOUND_IMPORT = 11,
    COM_DESCRIPTOR = 14,
    DEBUG = 6,
    DELAY_IMPORT = 13,
    EXCEPTION = 3,
    EXPORT = 0,
    GLOBALPTR = 8,
    IAT = 12,
    IMPORT = 1,
    LOAD_CONFIG = 10,
    RESOURCE = 2,
    SECURITY = 4,
    TLS = 9,
};
const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub fn getModuleHandle(allocator: std.mem.Allocator, module_name: ?[]const u8) !HMODULE {
    const peb = win.peb();

    if (module_name == null) return peb.ImageBaseAddress;

    const ldr = peb.Ldr;

    const first_link = ldr.InMemoryOrderModuleList.Flink;
    var current_link = first_link;

    while (true) {
        const module: *LDR_DATA_TABLE_ENTRY = @ptrCast(current_link);

        if (module.FullDllName.Buffer != null) {
            const module_name_utf16 = module.FullDllName.Buffer.?[0 .. module.FullDllName.Length / 2];
            const module_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(allocator, module_name_utf16);
            defer allocator.free(module_name_utf8);

            if (std.ascii.eqlIgnoreCase(module_name.?, module_name_utf8)) return @ptrCast(module.Reserved2[0]);
        }

        current_link = current_link.Flink;
        if (current_link == first_link) break;
    }

    return error.ModuleNotFound;
}

pub fn getProcAddress(h_module: HMODULE, proc_name: []const u8) !FARPROC {
    const module_base_address: [*]u8 = @ptrCast(h_module);

    const dos_header: *IMAGE_DOS_HEADER = @alignCast(@ptrCast(module_base_address));
    if (dos_header.e_magic != 0x5A4D) return error.InvalidModule;

    const e_lfanew: usize = @intCast(dos_header.e_lfanew);

    const file_header: *IMAGE_FILE_HEADER = @alignCast(@ptrCast(module_base_address + e_lfanew + 4));

    const nt_headers: IMAGE_NT_HEADERS = switch (file_header.Machine) {
        .AMD64 => blk: {
            const nt_headers_64: *IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(module_base_address + e_lfanew));
            break :blk .{ .nt64 = nt_headers_64 };
        },
        .I386 => blk: {
            const nt_headers_32: *IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(module_base_address + e_lfanew));
            break :blk .{ .nt32 = nt_headers_32 };
        },
        else => return error.InvalidModule,
    };

    const export_directory_rva = switch (nt_headers) {
        .nt64 => |nt_headers_64| nt_headers_64.OptionalHeader.DataDirectory[@intFromEnum(IMAGE_DIRECTORY_ENTRY.EXPORT)].VirtualAddress,
        .nt32 => |nt_headers_32| nt_headers_32.OptionalHeader.DataDirectory[@intFromEnum(IMAGE_DIRECTORY_ENTRY.EXPORT)].VirtualAddress,
    };

    const export_directory: *IMAGE_EXPORT_DIRECTORY = @alignCast(@ptrCast(module_base_address + export_directory_rva));

    const names: [*]u32 = @alignCast(@ptrCast(module_base_address + export_directory.AddressOfNames));
    const ordinals: [*]u16 = @alignCast(@ptrCast(module_base_address + export_directory.AddressOfNameOrdinals));
    const functions: [*]u32 = @alignCast(@ptrCast(module_base_address + export_directory.AddressOfFunctions));

    for (0..export_directory.NumberOfFunctions) |i| {
        const function_ordinal = ordinals[i];
        const function_name_rva = names[i];
        const function_name: [*:0]u8 = @ptrCast(module_base_address + function_name_rva);
        const function_rva = functions[function_ordinal];

        if (std.mem.eql(u8, proc_name, std.mem.span(function_name))) return @ptrCast(module_base_address + function_rva);
    }

    return error.ProcNotFound;
}
