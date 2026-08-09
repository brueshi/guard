const std = @import("std");

/// Shapes that look random but are structurally never credentials.
///
/// These are checked on the token itself, independent of surrounding
/// context, so they hold even when the token sits in an assignment.

/// Subresource Integrity and lockfile digests carry their algorithm inline,
/// which lands inside the token because `-` is a candidate character.
const digest_prefixes = [_][]const u8{
    "sha256-", "sha384-", "sha512-", "sha1-", "md5-", "blake3-",
};

/// Markers that a value is a stand-in a human is expected to replace.
/// Matched case-insensitively as substrings.
const placeholder_markers = [_][]const u8{
    "example",  "placeholder", "changeme", "change_me", "dummy",
    "redacted", "notarealkey", "fakekey",  "fake_key",  "testkey",
    "test_key", "replaceme",   "replace_me", "replace-me", "insertyour",
    "xxxxxx",   "aaaaaa",      "000000",   "123456789012",
};

/// `your` only counts as a placeholder marker at a word boundary, so
/// `your-api-key-here` matches while a random blob that happens to contain
/// the letters does not.
const boundary_markers = [_][]const u8{"your"};

fn containsAtBoundary(lowered: []const u8, needle: []const u8) bool {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, lowered, from, needle)) |at| {
        const before_ok = at == 0 or !std.ascii.isAlphanumeric(lowered[at - 1]);
        if (before_ok) return true;
        from = at + 1;
    }
    return false;
}

pub fn hasDigestPrefix(token: []const u8) bool {
    for (digest_prefixes) |p| {
        if (token.len > p.len and std.ascii.startsWithIgnoreCase(token, p)) return true;
    }
    return false;
}

/// True when the token carries an obvious "fill this in" marker, or has too
/// few distinct characters to be a real key of its length.
pub fn isPlaceholder(token: []const u8) bool {
    var buf: [256]u8 = undefined;
    if (token.len <= buf.len) {
        const lowered = buf[0..token.len];
        for (token, 0..) |c, i| lowered[i] = std.ascii.toLower(c);
        for (placeholder_markers) |m| {
            if (std.mem.indexOf(u8, lowered, m) != null) return true;
        }
        for (boundary_markers) |m| {
            if (containsAtBoundary(lowered, m)) return true;
        }
    }

    var seen = [_]bool{false} ** 256;
    var distinct: usize = 0;
    for (token) |c| {
        if (!seen[c]) {
            seen[c] = true;
            distinct += 1;
        }
    }
    // A genuine 20+ char credential draws from a wide alphabet. Anything
    // repeating a handful of characters is a mask or a filler run.
    return distinct <= 4;
}

/// Applied to known-provider matches as well as generic hits, so published
/// documentation fixtures stop tripping the scanner.
pub fn isKnownFixture(token: []const u8) bool {
    return isPlaceholder(token);
}

/// Character-set constants (`"ABCDEFGH...+/"`, `"0123456789abcdef"`) are
/// maximally high-entropy by construction: every character is distinct.
/// They show up wherever an encoder or ID generator is defined. A run of
/// consecutive code points this long does not occur in a real credential.
/// Measured as the share of characters sitting in an ascending run, not as
/// the longest run: a credential can contain `0123456789` by chance, but an
/// alphabet constant is ascending almost end to end.
const min_run = 3;
const sequential_share = 0.75;

pub fn isSequentialAlphabet(token: []const u8) bool {
    if (token.len < 16) return false;

    var in_runs: usize = 0;
    var i: usize = 0;
    while (i < token.len) {
        var j = i + 1;
        while (j < token.len and token[j] == token[j - 1] + 1) : (j += 1) {}
        const run = j - i;
        if (run >= min_run) in_runs += run;
        i = j;
    }

    const share = @as(f64, @floatFromInt(in_runs)) / @as(f64, @floatFromInt(token.len));
    return share >= sequential_share;
}

test "base64 and hex alphabets are recognised as constants" {
    try std.testing.expect(isSequentialAlphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"));
    try std.testing.expect(isSequentialAlphabet("0123456789abcdefghijklmnop"));
}

test "credentials are not sequential alphabets" {
    try std.testing.expect(!isSequentialAlphabet("aB3xQ9kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz"));
    try std.testing.expect(!isSequentialAlphabet("sk-ant-api03-aB3xQ9_kLm2nP5vR7wYzC8dFgHj1Kl"));
    // An incidental ascending run must not disqualify a real token.
    try std.testing.expect(!isSequentialAlphabet("sntrys_aB3xQ9kLm2nP5vR7wYzC8dF0123456789AbCdEfGh"));
}

test "sri digest prefix recognised" {
    try std.testing.expect(hasDigestPrefix("sha512-mzS9pfLOaMqJXbPVwPCK4h"));
    try std.testing.expect(hasDigestPrefix("sha384-ggOyR0iXCbMQv3Xipma34MD"));
    try std.testing.expect(!hasDigestPrefix("sk-ant-api03-aB3xQ9"));
}

test "aws documentation key is a known fixture" {
    try std.testing.expect(isKnownFixture("AKIAIOSFODNN7EXAMPLE"));
}

test "placeholder markers caught" {
    try std.testing.expect(isPlaceholder("your-api-key-here-replace-me"));
    try std.testing.expect(isPlaceholder("XXXXXXXXXXXXXXXXXXXXXXXX"));
    try std.testing.expect(isPlaceholder("CHANGEME_BEFORE_DEPLOYING"));
}

test "real credential is not a placeholder" {
    try std.testing.expect(!isPlaceholder("aB3xQ9kLm2nP5vR7wYzC8dFgHj1KlMnOpQrStUvWxYz"));
    try std.testing.expect(!isPlaceholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzK9mQ2pL7vN4tR"));
}

test "low distinct-character run is a placeholder" {
    try std.testing.expect(isPlaceholder("abababababababababababab"));
}
