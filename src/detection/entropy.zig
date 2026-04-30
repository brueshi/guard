const std = @import("std");

pub const default_threshold: f64 = 4.5;

pub const min_candidate_len: usize = 20;

pub fn shannon(s: []const u8) f64 {
    if (s.len == 0) return 0.0;
    var counts = [_]u32{0} ** 256;
    for (s) |c| counts[c] += 1;
    const len_f: f64 = @floatFromInt(s.len);
    var h: f64 = 0.0;
    for (counts) |n| {
        if (n == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(n)) / len_f;
        h -= p * @log2(p);
    }
    return h;
}

pub fn isCandidateChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.' or c == '+' or c == '/' or c == '=';
}

pub const Span = struct { start: usize, end: usize };

pub fn nextCandidate(input: []const u8, from: usize) ?Span {
    var i = from;
    while (i < input.len and !isCandidateChar(input[i])) : (i += 1) {}
    if (i >= input.len) return null;
    const start = i;
    while (i < input.len and isCandidateChar(input[i])) : (i += 1) {}
    return .{ .start = start, .end = i };
}

pub fn isHighEntropy(s: []const u8, threshold: f64) bool {
    if (s.len < min_candidate_len) return false;
    return shannon(s) >= threshold;
}

test "all-same-char string has zero entropy" {
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), shannon("aaaaaaaaaa"), 0.0001);
}

test "uniform 4-char alphabet has 2 bits per char" {
    try std.testing.expectApproxEqAbs(@as(f64, 2.0), shannon("abcdabcdabcd"), 0.0001);
}

test "real anthropic-shaped key crosses threshold" {
    const key = "sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp";
    try std.testing.expect(isHighEntropy(key, default_threshold));
}

test "short strings skipped" {
    try std.testing.expect(!isHighEntropy("aB3xQ9", default_threshold));
}

test "english prose stays below threshold" {
    try std.testing.expect(!isHighEntropy("the quick brown fox jumps over the lazy dog and runs away", default_threshold));
}

test "candidate scanner skips spaces and quotes" {
    const span = nextCandidate("key = \"abc123\"", 0).?;
    try std.testing.expectEqualStrings("key", "key = \"abc123\""[span.start..span.end]);
}
