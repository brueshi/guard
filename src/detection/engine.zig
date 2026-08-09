const std = @import("std");
const patterns = @import("patterns.zig");
const entropy = @import("entropy.zig");
const pem = @import("pem.zig");
const uri = @import("uri.zig");
const context = @import("context.zig");
const suppress = @import("suppress.zig");

const Allocator = std.mem.Allocator;

/// A byte range already claimed by an earlier detection pass; later passes
/// must skip candidates whose start falls inside one of these ranges so we
/// don't double-flag the same bytes.
pub const CoveredRange = struct { start: usize, end: usize };

fn isCovered(ranges: []const CoveredRange, pos: usize) bool {
    for (ranges) |r| {
        if (pos >= r.start and pos < r.end) return true;
    }
    return false;
}

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
    /// Report high-entropy tokens even with no credential context around
    /// them. Trades precision for recall on bare pastes.
    strict: bool = false,
    /// Emit hits for patterns that are public by design (Stripe
    /// publishable keys).
    include_publishable: bool = false,
    /// Byte ranges to leave alone entirely — diff hunks belonging to
    /// generated files. Sorted or not; membership is all that matters.
    exclude: []const CoveredRange = &.{},
};

/// `KEY=value` is a single candidate span, because `=` is a candidate
/// character. Narrow to the value so that provider prefixes line up with a
/// span start (`API_KEY=sk-ant-...` otherwise never matches the Anthropic
/// pattern at all) and so a redaction never swallows the variable name.
///
/// Base64 only ever uses `=` as trailing padding, so splitting on the last
/// `=` that still has content after it cannot cut a credential in half.
fn narrowToValue(input: []const u8, span: entropy.Span) entropy.Span {
    var i = span.end;
    while (i > span.start) : (i -= 1) {
        if (input[i - 1] != '=') continue;
        if (i < span.end) return .{ .start = i, .end = span.end };
        return span;
    }
    return span;
}

/// Decide whether an unrecognised token should be reported as a generic
/// secret. Ordered cheapest-first; each rejection is a distinct class of
/// false positive measured against real repositories.
fn isGenericSecret(input: []const u8, span: entropy.Span, opts: ScanOptions) bool {
    const token = input[span.start..span.end];
    if (token.len < entropy.min_candidate_len) return false;

    // Structural non-secrets: integrity digests and fill-me-in markers.
    if (suppress.hasDigestPrefix(token)) return false;
    if (suppress.isPlaceholder(token)) return false;
    if (suppress.isSequentialAlphabet(token)) return false;

    // Identifier chains and paths whose entropy comes from being long and
    // punctuated rather than from being random.
    if (entropy.isWordDecomposable(token)) return false;

    const ctx = context.classify(input, span.start);
    if (ctx.deny_label) return false;
    if (ctx.url_body and !opts.strict) return false;

    if (entropy.isHexToken(token)) {
        // Hex cannot clear the Shannon threshold, and git SHAs, checksums
        // and content digests all share the shape. Only an explicit
        // credential keyword makes a hex run worth reporting.
        return opts.strict or ctx.keyword;
    }

    if (!opts.strict and !(ctx.value_position or ctx.keyword)) return false;
    return entropy.isHighEntropy(token, opts.threshold);
}

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

    var covered: std.ArrayList(CoveredRange) = .empty;
    defer covered.deinit(allocator);

    // Pre-pass 1: multi-line PEM private key blocks. Emit one Hit per block
    // and add the range to `covered` so the token loop skips the body.
    const pem_spans = try pem.findBlocks(allocator, input);
    defer allocator.free(pem_spans);
    for (pem_spans) |s| {
        const value = input[s.start..s.end];
        if (isCovered(opts.exclude, s.start)) continue;
        if (opts.skip_noscan and lineHasNoscan(input, s.start)) continue;
        if (isAllowed(value, opts.allow)) continue;
        try hits.append(allocator, .{
            .kind = .known,
            .name = s.name,
            .start = s.start,
            .end = s.end,
        });
        try covered.append(allocator, .{ .start = s.start, .end = s.end });
    }

    // Pre-pass 2: URI-shaped connection strings. Emit one Hit per password
    // byte range (the rest of the URI stays intact) and cover the range.
    const uri_spans = try uri.findPasswordSpans(allocator, input);
    defer allocator.free(uri_spans);
    for (uri_spans) |sp| {
        const value = input[sp.start..sp.end];
        if (isCovered(opts.exclude, sp.start)) continue;
        if (opts.skip_noscan and lineHasNoscan(input, sp.start)) continue;
        if (isAllowed(value, opts.allow)) continue;
        try hits.append(allocator, .{
            .kind = .known,
            .name = "connection-string-password",
            .start = sp.start,
            .end = sp.end,
        });
        try covered.append(allocator, .{ .start = sp.start, .end = sp.end });
    }

    // Token pass: walk every candidate token. Skip anything inside a
    // covered range (already claimed by a pre-pass).
    var cursor: usize = 0;
    while (entropy.nextCandidate(input, cursor)) |raw_span| {
        if (isCovered(covered.items, raw_span.start) or isCovered(opts.exclude, raw_span.start)) {
            cursor = raw_span.end;
            continue;
        }
        const span = narrowToValue(input, raw_span);
        if (patterns.matchAt(input, span.start)) |m| {
            const value = input[m.start..m.end];
            const publishable = patterns.registry[m.pattern_index].publishable;
            if (!(opts.skip_noscan and lineHasNoscan(input, m.start)) and
                !isAllowed(value, opts.allow) and
                !suppress.isKnownFixture(value) and
                (opts.include_publishable or !publishable))
            {
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
            if (isGenericSecret(input, span, opts)) {
                if (!(opts.skip_noscan and lineHasNoscan(input, span.start)) and !isAllowed(token, opts.allow)) {
                    try hits.append(allocator, .{
                        .kind = .generic,
                        .name = "high-entropy-string",
                        .start = span.start,
                        .end = span.end,
                    });
                }
            }
            cursor = raw_span.end;
        }
    }

    // Pre-pass and token-pass hits are interleaved by .start; the redactor
    // assumes start-order, so sort before returning.
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

test "unquoted env assignment matches the provider pattern, not the whole line" {
    // '=' and '-' are both candidate characters, so this is one span. Before
    // narrowing, the prefix never lined up and the entropy fallback redacted
    // the variable name along with the key.
    const input = "ANTHROPIC_API_KEY=sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp\n";
    const hits = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("anthropic-api-key", hits[0].name);

    var r = Redactor.init(std.testing.allocator);
    defer r.deinit();
    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("ANTHROPIC_API_KEY=[REDACTED:anthropic-api-key:1]\n", out);
}

test "identifier chains and paths are not secrets" {
    const cases = [_][]const u8{
        "if (e.target.type !== monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN) return;\n",
        "const summaryPath = process.env.WORKBENCH_SUMMARY_PATH;\n",
        "  --billing-account=YOUR_BILLING_ACCOUNT_ID\n",
        "workload_identity_provider: projects/1017238569102/locations/global/workloadIdentityPools/gh-pool\n",
    };
    for (cases) |input| {
        const hits = try scan(std.testing.allocator, input, .{});
        defer std.testing.allocator.free(hits);
        try std.testing.expectEqual(@as(usize, 0), hits.len);
    }
}

test "integrity digests and public keys are not secrets" {
    const cases = [_][]const u8{
        "\"integrity\": \"sha512-mzS9pfLOaMqJXbPVwPCK4h/BJgFOQ9tGRVJ0OVKvHtIWQ8CXGaB3xQ9kLm2nP5vR7w==\"\n",
        "    sha512: JNsekz0K6qM0218/nhY8AO0pALCkiAl3WPjo+tpGhU/Owhf+AQGauddJoE7GKKFXjODYabb2rA==\n",
        "github.com/spf13/cobra v1.8.0/go.mod h1:WXLWApfZ71AjXPya3WOlMsY9yMs7YeiHhFVlvLyhcho=\n",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ8kL3mNp2QrXvYw7TcFbHjKlMnOpQrStUvWxYz01 me@host\n",
        "background: url(\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAA\")\n",
    };
    for (cases) |input| {
        const hits = try scan(std.testing.allocator, input, .{});
        defer std.testing.allocator.free(hits);
        try std.testing.expectEqual(@as(usize, 0), hits.len);
    }
}

test "documentation fixtures and publishable keys are not redacted" {
    const inputs = [_][]const u8{
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        "STRIPE_PUBLISHABLE_KEY=pk_test_51H8xQ2KlMnOpQrStUvWxYz0123456789AbCdEf\n",
    };
    for (inputs) |input| {
        const hits = try scan(std.testing.allocator, input, .{});
        defer std.testing.allocator.free(hits);
        try std.testing.expectEqual(@as(usize, 0), hits.len);
    }
}

test "publishable keys reported when explicitly requested" {
    const input = "STRIPE_PUBLISHABLE_KEY=pk_test_51H8xQ2KlMnOpQrStUvWxYz0123456789AbCdEf\n";
    const hits = try scan(std.testing.allocator, input, .{ .include_publishable = true });
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("stripe-publishable-key", hits[0].name);
}

test "hex secret needs a credential keyword, a digest does not qualify" {
    const secret = "SESSION_SECRET=\"7f3a9c2e18b4d605c9e2b1a8d0f7c3e5b6a9d243f8e1c0b7a5d9f2e4c6b8a0d13\"\n";
    const hits = try scan(std.testing.allocator, secret, .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 1), hits.len);

    const checksum = "checksum = \"d0c1e5a8f3b7924c6e0a1d8f4b2c7e93a5f6d0b8c3e1a7f9d2b4c6e8a0f3d5b7\"\n";
    const none = try scan(std.testing.allocator, checksum, .{});
    defer std.testing.allocator.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);

    const sha = "commit 9f8c2b1e4a7d036f5b8e2c1a9d4f7b3e6c0a8d25\n";
    const no_sha = try scan(std.testing.allocator, sha, .{});
    defer std.testing.allocator.free(no_sha);
    try std.testing.expectEqual(@as(usize, 0), no_sha.len);
}

test "strict mode restores ungated entropy reporting" {
    const input = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ8kL3mNp2QrXvYw7TcFbHjKlMnOpQrStUvWxYz01 me@host\n";
    const gated = try scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(gated);
    try std.testing.expectEqual(@as(usize, 0), gated.len);

    const strict = try scan(std.testing.allocator, input, .{ .strict = true });
    defer std.testing.allocator.free(strict);
    try std.testing.expect(strict.len > 0);
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
