const std = @import("std");
const win = std.os.windows;

const HMODULE = win.HMODULE;
const LDR_DATA_TABLE_ENTRY = win.LDR_DATA_TABLE_ENTRY;

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
