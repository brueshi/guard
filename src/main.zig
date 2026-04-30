const std = @import("std");
const engine = @import("detection/engine.zig");
const entropy = @import("detection/entropy.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const usage =
    \\guard - redact secrets from stdin to stdout
    \\
    \\usage:
    \\  guard [redact] [flags]      read stdin, write redacted stdout
    \\
    \\flags:
    \\  --summary                   write human report to stderr
    \\  --json                      write JSON report to stderr
    \\  --entropy-threshold <f>     override entropy cutoff (default 4.5)
    \\  -h, --help                  show this help
    \\
    \\exit codes:
    \\  0  no secrets detected
    \\  1  one or more secrets redacted
    \\  2  invocation error
    \\
;

const Mode = enum { plain, summary, json };

const Args = struct {
    mode: Mode = .plain,
    threshold: f64 = entropy.default_threshold,
};

const ParseError = error{ HelpRequested, UnknownArg, MissingValue, InvalidNumber };

fn parseArgs(it: *std.process.Args.Iterator) ParseError!Args {
    var args = Args{};
    _ = it.next(); // argv[0]

    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "redact")) continue;
        if (std.mem.eql(u8, a, "--summary")) {
            args.mode = .summary;
        } else if (std.mem.eql(u8, a, "--json")) {
            args.mode = .json;
        } else if (std.mem.eql(u8, a, "--entropy-threshold")) {
            const val = it.next() orelse return error.MissingValue;
            args.threshold = std.fmt.parseFloat(f64, val) catch return error.InvalidNumber;
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            return error.HelpRequested;
        } else {
            return error.UnknownArg;
        }
    }
    return args;
}

fn readAll(allocator: Allocator, r: *Io.Reader) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    while (true) {
        _ = r.peek(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const n = r.bufferedLen();
        try buf.appendSlice(allocator, r.buffered()[0..n]);
        r.toss(n);
    }
    return try buf.toOwnedSlice(allocator);
}

fn writeSummary(w: *Io.Writer, hits: []const engine.Hit, allocator: Allocator) !void {
    if (hits.len == 0) {
        try w.writeAll("[guard] 0 hits  stdout passed through unchanged\n");
        try w.writeAll("---\n");
        try w.writeAll("[guard] stdout is clean  safe to paste\n");
        return;
    }

    var counts = std.StringHashMap(u32).init(allocator);
    defer counts.deinit();
    for (hits) |h| {
        const gop = try counts.getOrPut(h.name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    try w.print("[guard] scan complete  {d} hits\n", .{hits.len});
    var it = counts.iterator();
    while (it.next()) |entry| {
        try w.print("  {s:<28} {d}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    try w.writeAll("---\n");
    try w.writeAll("[guard] stdout is clean  safe to paste\n");
}

fn writeJson(w: *Io.Writer, hits: []const engine.Hit, allocator: Allocator) !void {
    var counts = std.StringHashMap(u32).init(allocator);
    defer counts.deinit();
    for (hits) |h| {
        const gop = try counts.getOrPut(h.name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    try w.print("{{\"hits\":{d},\"by_type\":{{", .{hits.len});
    var first = true;
    var it = counts.iterator();
    while (it.next()) |entry| {
        if (!first) try w.writeAll(",");
        first = false;
        try w.print("\"{s}\":{d}", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    try w.writeAll("}}\n");
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = Io.File.stderr().writer(io, &stderr_buf);
    const serr = &stderr_writer.interface;

    var arg_it = init.minimal.args.iterate();
    const args = parseArgs(&arg_it) catch |err| switch (err) {
        error.HelpRequested => {
            try serr.writeAll(usage);
            try serr.flush();
            return;
        },
        error.UnknownArg, error.MissingValue, error.InvalidNumber => {
            try serr.writeAll("error: invalid arguments\n\n");
            try serr.writeAll(usage);
            try serr.flush();
            std.process.exit(2);
        },
    };

    var stdin_buf: [4096]u8 = undefined;
    var stdout_buf: [4096]u8 = undefined;

    var stdin_reader = Io.File.stdin().reader(io, &stdin_buf);
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buf);

    const r = &stdin_reader.interface;
    const sout = &stdout_writer.interface;

    const input = try readAll(allocator, r);
    defer allocator.free(input);

    const hits = try engine.scan(allocator, input, args.threshold);
    defer allocator.free(hits);

    var redactor = engine.Redactor.init(allocator);
    defer redactor.deinit();

    const out = try redactor.redact(input, hits);
    defer allocator.free(out);

    try sout.writeAll(out);
    try sout.flush();

    switch (args.mode) {
        .plain => {},
        .summary => {
            try writeSummary(serr, hits, allocator);
            try serr.flush();
        },
        .json => {
            try writeJson(serr, hits, allocator);
            try serr.flush();
        },
    }

    if (hits.len > 0) std.process.exit(1);
}
