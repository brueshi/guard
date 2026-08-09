const std = @import("std");

/// What the bytes around a candidate token say about whether it is a value
/// that could plausibly hold a credential.
///
/// The generic entropy rule has no provider prefix to anchor on, so without
/// this it fires on any sufficiently random-looking run of characters
/// anywhere in a file. Real credentials are almost always *values*: they sit
/// after an `=` or `:`, or on a line that names what they are. Gating on that
/// is what separates `API_KEY = "<blob>"` from an operand in an expression.
pub const Context = struct {
    /// Token sits directly after `=` or `:`, optionally through one quote.
    value_position: bool = false,
    /// A credential-ish word appears earlier on the same line.
    keyword: bool = false,
    /// The label immediately before the token names a known non-secret
    /// (a digest, an integrity hash, a source map).
    deny_label: bool = false,
    /// Token is the host+path body of a URL. Credentials passed in a query
    /// string end up in their own span, so nothing is lost by skipping this.
    url_body: bool = false,
};

/// How far back to look for a credential-naming word. A secret's label sits
/// immediately before it; scanning further just raises the odds of an
/// unrelated match, and minified bundles put an entire file on one line.
const keyword_window = 64;

/// Words that name a credential. Matched case-insensitively against the
/// portion of the line preceding the token. High entropy is still required
/// on top of this, so a loose match here costs little.
const key_words = [_][]const u8{
    "key",     "token",  "secret",     "password", "passwd",
    "pwd",     "auth",   "credential", "bearer",   "api",
    "private", "sign",   "session",    "cookie",   "salt",
    "access",  "client", "cert",       "jwt",      "hmac",
};

/// Labels whose values are high-entropy by construction and never secret.
/// Checked against the identifier immediately before the separator, so
/// `integrity:` matches but a line merely mentioning integrity does not.
const deny_labels = [_][]const u8{
    "integrity", "checksum", "digest",  "hash",    "etag",
    "sha",       "sha1",     "sha256",  "sha384",  "sha512",
    "md5",       "h1",       "mappings", "fingerprint", "resolved",
    "base64",    "revision", "commit",  "blake3",  "crc",
};

fn lineStart(input: []const u8, pos: usize) usize {
    var i = pos;
    while (i > 0 and input[i - 1] != '\n') : (i -= 1) {}
    return i;
}

fn isLabelChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-';
}

/// Walk back over `<space>* <quote>? <space>*` and report the separator we
/// land on, plus where the label before it ends.
fn separatorBefore(input: []const u8, start: usize, from: usize) ?struct { sep: u8, label_end: usize } {
    var i = from;
    while (i > start and (input[i - 1] == ' ' or input[i - 1] == '\t')) : (i -= 1) {}
    if (i > start and (input[i - 1] == '"' or input[i - 1] == '\'' or input[i - 1] == '`')) i -= 1;
    while (i > start and (input[i - 1] == ' ' or input[i - 1] == '\t')) : (i -= 1) {}
    if (i == start) return null;
    const c = input[i - 1];
    if (c != '=' and c != ':') return null;
    // `!==`, `===`, `<=`, `>=` compare rather than assign, so what follows
    // is an operand, not a value. Without this every equality check against
    // a long constant reads as a credential assignment.
    if (c == '=' and i - 1 > start) {
        switch (input[i - 2]) {
            '!', '=', '<', '>' => return null,
            else => {},
        }
    }
    return .{ .sep = c, .label_end = i - 1 };
}

pub fn classify(input: []const u8, token_start: usize) Context {
    var ctx = Context{};
    const ls = lineStart(input, token_start);
    const before = input[ls..token_start];

    if (separatorBefore(input, ls, token_start)) |s| {
        // `scheme://host/path` puts a ':' right before the token even though
        // nothing here is an assignment. Treat it as a URL, not a value.
        ctx.url_body = token_start < input.len and input[token_start] == '/';
        ctx.value_position = !ctx.url_body;

        // Identify the label that the separator belongs to.
        var e = s.label_end;
        while (e > ls and (input[e - 1] == ' ' or input[e - 1] == '\t')) : (e -= 1) {}
        if (e > ls and (input[e - 1] == '"' or input[e - 1] == '\'')) e -= 1;
        var b = e;
        while (b > ls and isLabelChar(input[b - 1])) : (b -= 1) {}
        if (e > b) {
            const label = input[b..e];
            for (deny_labels) |d| {
                if (std.ascii.eqlIgnoreCase(label, d)) {
                    ctx.deny_label = true;
                    break;
                }
            }
        }
    }

    var buf: [keyword_window]u8 = undefined;
    const n = @min(before.len, buf.len);
    const lowered = buf[0..n];
    for (before[before.len - n ..], 0..) |c, i| lowered[i] = std.ascii.toLower(c);
    for (key_words) |w| {
        if (std.mem.indexOf(u8, lowered, w) != null) {
            ctx.keyword = true;
            break;
        }
    }

    return ctx;
}

test "assignment is a value position" {
    const input = "API_KEY = \"abc\"";
    const ctx = classify(input, std.mem.indexOf(u8, input, "abc").?);
    try std.testing.expect(ctx.value_position);
    try std.testing.expect(ctx.keyword);
}

test "yaml colon is a value position" {
    const input = "secret: abc";
    const ctx = classify(input, std.mem.indexOf(u8, input, "abc").?);
    try std.testing.expect(ctx.value_position);
    try std.testing.expect(ctx.keyword);
}

test "bare operand is neither value nor keyword" {
    const input = "if (e.target.type !== monaco.editor.MouseTargetType.GUTTER) return;";
    const ctx = classify(input, std.mem.indexOf(u8, input, "monaco").?);
    try std.testing.expect(!ctx.value_position);
    try std.testing.expect(!ctx.keyword);
}

test "url scheme colon is not a value position" {
    const input = "careers_url: \"https://example.com/Senior-Engineer-2578bd0e6a\"";
    const ctx = classify(input, std.mem.indexOf(u8, input, "//example").?);
    try std.testing.expect(!ctx.value_position);
}

test "integrity label is denied" {
    const input = "\"integrity\": \"sha512-mzS9pfLOaMqJ\"";
    const ctx = classify(input, std.mem.indexOf(u8, input, "sha512").?);
    try std.testing.expect(ctx.deny_label);
}

test "go.sum h1 label is denied" {
    const input = "github.com/spf13/cobra v1.8.0/go.mod h1:WXLWApfZ71AjXPya3WOlMsY9yMs7YeiHhFVlvLyhcho=";
    const ctx = classify(input, std.mem.indexOf(u8, input, "WXLW").?);
    try std.testing.expect(ctx.deny_label);
}

test "ssh public key line has no credential context" {
    const input = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ8kL3mNp2QrXvYw7 user@host";
    const ctx = classify(input, std.mem.indexOf(u8, input, "AAAAB3").?);
    try std.testing.expect(!ctx.value_position);
    try std.testing.expect(!ctx.keyword);
}
