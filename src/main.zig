const std = @import("std");

pub fn main() !void {
    var stdin_buf: [4096]u8 = undefined;
    var stdout_buf: [4096]u8 = undefined;

    const io = std.Io.Threaded.global_single_threaded.io();
    var file_reader = std.Io.File.stdin().reader(io, &stdin_buf);
    var file_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const r = &file_reader.interface;
    const w = &file_writer.interface;

    while (true) {
        _ = r.peek(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const n = r.bufferedLen();
        try w.writeAll(r.buffered()[0..n]);
        r.toss(n);
    }

    try w.flush();
}
