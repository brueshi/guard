const std = @import("std");
const patterns = @import("patterns.zig");
const entropy = @import("entropy.zig");
const pem = @import("pem.zig");

const Allocator = std.mem.Allocator;

pub const HitKind = enum { known, generic };

pub const Hit = struct {
    kind: HitKind,
    name: []const u8,
    start: usize,
    end: usize,
};

pub const ScanOptions = struct {
    threshold: f64 = entropy.default_threshold,
    allow: []const []const u8 = &.{},
    skip_noscan: bool = true,
};

fn lineHasNoscan(input: []const u8, pos: usize) bool {
    var line_start: usize = pos;
    while (line_start > 0 and input[line_start - 1] != '\n') : (line_start -= 1) {}
    var line_end: usize = pos;
    while (line_end < input.len and input[line_end] != '\n') : (line_end += 1) {}
    const line = input[line_start..line_end];
    return std.mem.indexOf(u8, line, "# noscan") != null or
        std.mem.indexOf(u8, line, "// noscan") != null;
}

fn isAllowed(value: []const u8, allow: []const []const u8) bool {
    for (allow) |pat| {
        if (std.mem.indexOf(u8, value, pat) != null) return true;
    }
    return false;
}

pub fn scan(allocator: Allocator, input: []const u8, opts: ScanOptions) ![]Hit {
    var hits: std.ArrayList(Hit) = .empty;
    errdefer hits.deinit(allocator);

    // First pass: locate multi-line PEM blocks. We emit one Hit per block and
    // track their ranges so the token-scan pass below skips anything inside.
    const pem_spans = try pem.findBlocks(allocator, input);
    defer allocator.free(pem_spans);

    var pem_idx: usize = 0;
    for (pem_spans) |s| {
        const value = input[s.start..s.end];
        if (opts.skip_noscan and lineHasNoscan(input, s.start)) continue;
        if (isAllowed(value, opts.allow)) continue;
        try hits.append(allocator, .{
            .kind = .known,
            .name = s.name,
            .start = s.start,
            .end = s.end,
        });
    }
    // Hits emitted from pem_spans are already sorted by .start because
    // findBlocks walks left-to-right.

    var cursor: usize = 0;
    while (entropy.nextCandidate(input, cursor)) |span| {
        // Advance pem_idx past any covered range that ends before this span.
        while (pem_idx < pem_spans.len and pem_spans[pem_idx].end <= span.start) : (pem_idx += 1) {}
        // If span.start falls inside a PEM block, skip past the block.
        if (pem_idx < pem_spans.len and span.start >= pem_spans[pem_idx].start and span.start < pem_spans[pem_idx].end) {
            cursor = pem_spans[pem_idx].end;
            continue;
        }

        if (patterns.matchAt(input, span.start)) |m| {
            const value = input[m.start..m.end];
            if (!(opts.skip_noscan and lineHasNoscan(input, m.start)) and !isAllowed(value, opts.allow)) {
                try hits.append(allocator, .{
                    .kind = .known,
                    .name = m.name(),
                    .start = m.start,
                    .end = m.end,
                });
            }
            cursor = m.end;
        } else {
            const token = input[span.start..span.end];
            if (entropy.isHighEntropy(token, opts.threshold)) {
                if (!(opts.skip_noscan and lineHasNoscan(input, span.start)) and !isAllowed(token, opts.allow)) {
                    try hits.append(allocator, .{
                        .kind = .generic,
                        .name = "high-entropy-string",
                        .start = span.start,
                        .end = span.end,
                    });
                }
            }
            cursor = span.end;
        }
    }

    // Token-pass hits land after PEM hits in `hits`, but their starts may
    // interleave (PEM blocks can sit between tokens). Sort to honour the
    // contract that the redactor consumes hits in start-order.
    const out = try hits.toOwnedSlice(allocator);
    std.mem.sort(Hit, out, {}, struct {
        fn lessThan(_: void, a: Hit, b: Hit) bool {
            return a.start < b.start;
        }
    }.lessThan);
    return out;
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
    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("anthropic-api-key", hits[0].name);
}

test "noscan comment skips detection on that line" {
    const input =
        "real = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "fake = \"sk-ant-api03-DiFfErEnT_xyz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789DiFfErEnT\" // noscan\n";
    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
}

test "allowlist substring drops matching hit" {
    const input = "key = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n";
    const allow = [_][]const u8{"aB3xQ9_kLm2nP5vR7"};
    const hits = try scan(std.testing.allocator, input, .{ .allow = &allow });
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "redactor produces stable counter placeholders" {
    const input =
        "key1 = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "key1_again = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "key2 = \"sk-ant-api03-DIFFERENT_xyz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789DiFfErEnT\"\n";

    const hits = try scan(std.testing.allocator, input, .{});
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
    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);

    var r = Redactor.init(std.testing.allocator);
    defer r.deinit();
    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(input, out);
}

test "PEM block round-trips through scan + redactor as a single hit" {
    const input =
        "before\n" ++
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n" ++
        "hijklmnop1234567890qrstuvwxyz\n" ++
        "-----END RSA PRIVATE KEY-----\n" ++
        "after\n";

    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);

    // Exactly one hit — the multi-line block — not multiple per-line entropy hits.
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("rsa-private-key", hits[0].name);

    var r = Redactor.init(std.testing.allocator);
    defer r.deinit();
    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "[REDACTED:rsa-private-key:1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "BEGIN RSA PRIVATE KEY") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "MIIEpAIBAAKCAQEA") == null);
    try std.testing.expect(std.mem.startsWith(u8, out, "before\n"));
    try std.testing.expect(std.mem.endsWith(u8, out, "after\n"));
}

test "PEM body lines are not double-flagged as high-entropy" {
    // Body lines on their own would be high-entropy candidates; the PEM pass
    // must claim the range so the token loop skips them.
    const input =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy\n" ++
        "NTUxOQAAACA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR==\n" ++
        "-----END OPENSSH PRIVATE KEY-----\n";

    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);

    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("openssh-private-key", hits[0].name);
}

test "PEM block alongside a token secret yields ordered hits" {
    const input =
        "tok = \"sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\"\n" ++
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n" ++
        "-----END RSA PRIVATE KEY-----\n" ++
        "tok2 = \"sk-ant-api03-DIFFERENT_xyz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789DiFfErEnT\"\n";

    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);

    try std.testing.expectEqual(@as(usize, 3), hits.len);
    // Sort contract: starts must be strictly increasing.
    try std.testing.expect(hits[0].start < hits[1].start);
    try std.testing.expect(hits[1].start < hits[2].start);
    try std.testing.expectEqualStrings("anthropic-api-key", hits[0].name);
    try std.testing.expectEqualStrings("rsa-private-key", hits[1].name);
    try std.testing.expectEqualStrings("anthropic-api-key", hits[2].name);
}

test "noscan on the BEGIN line suppresses the PEM hit" {
    // PEM blocks span multiple lines, so the existing per-line noscan check
    // only fires when the directive sits on the BEGIN line itself. Document
    // that contract here.
    const input =
        "-----BEGIN RSA PRIVATE KEY----- // noscan\n" ++
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n" ++
        "-----END RSA PRIVATE KEY-----\n";

    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "noscan on a neighbouring line does not suppress the PEM hit" {
    const input =
        "// noscan\n" ++
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n" ++
        "-----END RSA PRIVATE KEY-----\n";

    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("rsa-private-key", hits[0].name);
}

test "allowlist substring drops a matching PEM block" {
    const input =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA1234567890SAMPLEFIXTURE\n" ++
        "-----END RSA PRIVATE KEY-----\n";

    const allow = [_][]const u8{"SAMPLEFIXTURE"};
    const hits = try scan(std.testing.allocator, input, .{ .allow = &allow });
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}
