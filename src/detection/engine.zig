const std = @import("std");
const patterns = @import("patterns.zig");
const entropy = @import("entropy.zig");

const Allocator = std.mem.Allocator;

pub const HitKind = enum { known, generic };

pub const Hit = struct {
    kind: HitKind,
    name: []const u8,
    start: usize,
    end: usize,
};

pub fn scan(allocator: Allocator, input: []const u8, threshold: f64) ![]Hit {
    var hits: std.ArrayList(Hit) = .empty;
    errdefer hits.deinit(allocator);

    var cursor: usize = 0;
    while (entropy.nextCandidate(input, cursor)) |span| {
        if (patterns.matchAt(input, span.start)) |m| {
            try hits.append(allocator, .{
                .kind = .known,
                .name = m.name(),
                .start = m.start,
                .end = m.end,
            });
            cursor = m.end;
        } else {
            const token = input[span.start..span.end];
            if (entropy.isHighEntropy(token, threshold)) {
                try hits.append(allocator, .{
                    .kind = .generic,
                    .name = "high-entropy-string",
                    .start = span.start,
                    .end = span.end,
                });
            }
            cursor = span.end;
        }
    }

    return try hits.toOwnedSlice(allocator);
}

pub const Redactor = struct {
    allocator: Allocator,
    counters: std.StringHashMap(u32),
    seen: std.StringHashMap([]const u8),
    /// Strings owned by this redactor and freed in deinit.
    owned: std.ArrayList([]u8),

    pub fn init(allocator: Allocator) Redactor {
        return .{
            .allocator = allocator,
            .counters = std.StringHashMap(u32).init(allocator),
            .seen = std.StringHashMap([]const u8).init(allocator),
            .owned = .empty,
        };
    }

    pub fn deinit(r: *Redactor) void {
        r.counters.deinit();
        r.seen.deinit();
        for (r.owned.items) |s| r.allocator.free(s);
        r.owned.deinit(r.allocator);
    }

    fn placeholderFor(r: *Redactor, name: []const u8, secret: []const u8) ![]const u8 {
        if (r.seen.get(secret)) |existing| return existing;

        const gop = try r.counters.getOrPut(name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        const id = gop.value_ptr.*;

        const placeholder = try std.fmt.allocPrint(
            r.allocator,
            "[REDACTED:{s}:{d}]",
            .{ name, id },
        );
        try r.owned.append(r.allocator, placeholder);

        const secret_copy = try r.allocator.dupe(u8, secret);
        try r.owned.append(r.allocator, secret_copy);
        try r.seen.put(secret_copy, placeholder);

        return placeholder;
    }

    pub fn redact(r: *Redactor, input: []const u8, hits: []const Hit) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(r.allocator);

        var i: usize = 0;
        for (hits) |h| {
            try out.appendSlice(r.allocator, input[i..h.start]);
            const placeholder = try r.placeholderFor(h.name, input[h.start..h.end]);
            try out.appendSlice(r.allocator, placeholder);
            i = h.end;
        }
        try out.appendSlice(r.allocator, input[i..]);

        return try out.toOwnedSlice(r.allocator);
    }
};

test "scan finds anthropic key in surrounding code" {
    const input = "const key = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\";";
    const hits = try scan(std.testing.allocator, input, entropy.default_threshold);
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("anthropic-api-key", hits[0].name);
}

test "redactor produces stable counter placeholders" {
    const input =
        "key1 = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "key1_again = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "key2 = \"sk-ant-api03-DIFFERENT_xyz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789DiFfErEnT\"\n";

    const hits = try scan(std.testing.allocator, input, entropy.default_threshold);
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 3), hits.len);

    var r = Redactor.init(std.testing.allocator);
    defer r.deinit();
    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "[REDACTED:anthropic-api-key:1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[REDACTED:anthropic-api-key:2]") != null);
    // The duplicate should reuse :1, not become :3
    try std.testing.expect(std.mem.count(u8, out, "[REDACTED:anthropic-api-key:1]") == 2);
    try std.testing.expect(std.mem.indexOf(u8, out, "[REDACTED:anthropic-api-key:3]") == null);
}

test "no secrets means input passes through unchanged" {
    const input = "fn add(a: i32, b: i32) i32 { return a + b; }\n";
    const hits = try scan(std.testing.allocator, input, entropy.default_threshold);
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);

    var r = Redactor.init(std.testing.allocator);
    defer r.deinit();
    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(input, out);
}
