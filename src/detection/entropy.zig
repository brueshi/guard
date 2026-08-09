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

/// Hex runs top out at 4 bits/char, so `isHighEntropy` can never fire on
/// them at any sane threshold. Length is the only usable signal, which is
/// why callers gate hex on an explicit credential keyword instead.
pub const hex_min_len: usize = 32;

pub fn isHexToken(s: []const u8) bool {
    if (s.len < hex_min_len) return false;
    var has_digit = false;
    var has_alpha = false;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            has_digit = true;
        } else if ((c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
            has_alpha = true;
        } else return false;
    }
    return has_digit and has_alpha;
}

fn isSegmentSeparator(c: u8) bool {
    return c == '.' or c == '/' or c == '=' or c == '-' or c == '_' or c == '+';
}

/// True when every separator-delimited segment is uniformly one character
/// class — all letters or all digits.
///
/// Shannon entropy measures bits per character, so a long span that mixes
/// case, digits and punctuation scores high even when it is plainly not a
/// secret. Because `isCandidateChar` accepts `. / = - _ +`, a "token" here
/// is often a whole dotted identifier chain, resource path or `--flag=WORD`
/// pair, and gluing ordinary words together is enough to clear the
/// threshold on length alone:
///
///   YOUR_BILLING_ACCOUNT_ID                   -> 3.68 (below)
///   --billing-account=YOUR_BILLING_ACCOUNT_ID -> 4.57 (above)
///
/// Decomposing first tells the two apart. Real credentials survive this
/// test because at least one segment mixes letters and digits — an AWS
/// secret key splits on '/' into segments like "K7MDENG", never into a
/// list of clean words.
pub fn isWordDecomposable(s: []const u8) bool {
    var i: usize = 0;
    var segments: usize = 0;
    while (i < s.len) {
        while (i < s.len and isSegmentSeparator(s[i])) : (i += 1) {}
        if (i >= s.len) break;
        const start = i;
        var has_alpha = false;
        var has_digit = false;
        while (i < s.len and !isSegmentSeparator(s[i])) : (i += 1) {
            if (std.ascii.isAlphabetic(s[i])) has_alpha = true else if (std.ascii.isDigit(s[i])) has_digit = true else return false;
        }
        if (i == start) continue;
        if (has_alpha and has_digit) return false;
        segments += 1;
    }
    return segments > 0;
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

test "dotted identifier chain decomposes into words" {
    try std.testing.expect(isWordDecomposable("monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN"));
    try std.testing.expect(isWordDecomposable("process.env.WORKBENCH_SUMMARY_PATH"));
}

test "flag glued to its value decomposes into words" {
    // Each half is below threshold; concatenation alone pushes it over.
    try std.testing.expect(isHighEntropy("--billing-account=YOUR_BILLING_ACCOUNT_ID", default_threshold));
    try std.testing.expect(isWordDecomposable("--billing-account=YOUR_BILLING_ACCOUNT_ID"));
}

test "resource path with numeric segment decomposes" {
    try std.testing.expect(isWordDecomposable("projects/1017238569102/locations/global/workloadIdentityPools/github-pool"));
}

test "credentials do not decompose into words" {
    try std.testing.expect(!isWordDecomposable("aB3xQ9kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz"));
    // AWS secret keys split on '/' but the segments still mix classes.
    try std.testing.expect(!isWordDecomposable("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzK9mQ2pL7vN4tR"));
}

test "hex token recognised only at length" {
    try std.testing.expect(isHexToken("7f3a9c2e18b4d605c9e2b1a8d0f7c3e5b6a9d243f8e1c0b7a5d9f2e4c6b8a0d13"));
    try std.testing.expect(!isHexToken("7f3a9c2e"));
    try std.testing.expect(!isHexToken("aB3xQ9kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz"));
}

test "hex never clears the shannon threshold" {
    // Justifies the separate keyword-gated path for hex.
    const sha = "7f3a9c2e18b4d605c9e2b1a8d0f7c3e5b6a9d243f8e1c0b7a5d9f2e4c6b8a0d13";
    try std.testing.expect(!isHighEntropy(sha, default_threshold));
}

test "candidate scanner skips spaces and quotes" {
    const span = nextCandidate("key = \"abc123\"", 0).?;
    try std.testing.expectEqualStrings("key", "key = \"abc123\""[span.start..span.end]);
}
