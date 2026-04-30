const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Span = struct { start: usize, end: usize };

/// Schemes for which we will redact embedded passwords. Lower-case;
/// matching is performed case-insensitively.
const supported_schemes = [_][]const u8{
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "https",
    "http",
    "ftp",
    "sftp",
    "s3",
    "kafka",
    "ldap",
    "ldaps",
};

/// RFC3986 scheme charset: ALPHA / DIGIT / "+" / "-" / "."
fn isSchemeChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.';
}

/// RFC3986 userinfo subset (excluding ':' so we can split user:pass).
/// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
/// We keep ':' as the splitter and treat everything else as userinfo bytes.
fn isUserInfoChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '.', '_', '~', '-',
        '%',
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=',
        => true,
        else => false,
    };
}

fn schemeIsSupported(scheme: []const u8) bool {
    for (supported_schemes) |s| {
        if (scheme.len != s.len) continue;
        if (std.ascii.eqlIgnoreCase(scheme, s)) return true;
    }
    return false;
}

/// Walk `input` looking for `<scheme>://<user>:<password>@<host>...` and
/// return only the password byte ranges. Allocator owns the returned slice.
pub fn findPasswordSpans(allocator: Allocator, input: []const u8) ![]Span {
    var spans: std.ArrayList(Span) = .empty;
    errdefer spans.deinit(allocator);

    var i: usize = 0;
    while (i + 3 <= input.len) {
        if (input[i] != ':' or input[i + 1] != '/' or input[i + 2] != '/') {
            i += 1;
            continue;
        }

        // Walk back to find the scheme.
        var s_start = i;
        while (s_start > 0 and isSchemeChar(input[s_start - 1])) : (s_start -= 1) {}
        const scheme = input[s_start..i];

        if (scheme.len == 0 or !schemeIsSupported(scheme)) {
            i += 3;
            continue;
        }

        // Look at userinfo: starts after "://".
        const ui_start = i + 3;
        var p: usize = ui_start;
        var colon_pos: ?usize = null;
        while (p < input.len) : (p += 1) {
            const c = input[p];
            if (c == ':') {
                if (colon_pos == null) colon_pos = p;
                // Multiple colons inside userinfo aren't valid for our purpose.
                // We use the first ':' as the user/password split.
                continue;
            }
            if (c == '@') break;
            if (c == '/' or c == '?' or c == '#') break;
            if (std.ascii.isWhitespace(c)) break;
            if (!isUserInfoChar(c)) break;
        }

        // Need an '@' terminator and a colon to form user:pass@.
        if (p < input.len and input[p] == '@') {
            if (colon_pos) |cp| {
                const user_start = ui_start;
                const user_end = cp;
                const pass_start = cp + 1;
                const pass_end = p;
                // Need a non-empty user and non-empty password.
                if (user_end > user_start and pass_end > pass_start) {
                    try spans.append(allocator, .{ .start = pass_start, .end = pass_end });
                }
            }
        }

        // Advance past whatever userinfo region we walked, even on no-match,
        // to avoid re-scanning the same "://".
        i = if (p > i + 3) p else i + 3;
    }

    return try spans.toOwnedSlice(allocator);
}

test "postgres URI with password yields password span only" {
    const input = "DATABASE_URL=\"postgres://app_user:hunter2@db.local:5432/prod\"";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("hunter2", input[spans[0].start..spans[0].end]);
}

test "mongodb+srv URI matches" {
    const input = "uri = mongodb+srv://admin:s3cret@cluster0.example.mongodb.net/test";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("s3cret", input[spans[0].start..spans[0].end]);
}

test "https URI with basic auth matches" {
    const input = "url=https://alice:wonderland@api.example.com/v1/widgets";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("wonderland", input[spans[0].start..spans[0].end]);
}

test "URI with no userinfo does not match" {
    const input = "https://example.com/path";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "URI with userinfo but no password does not match" {
    const input = "ftp://onlyuser@host.example.com/file";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "URI with empty password does not match" {
    const input = "ftp://user:@host.example.com/file";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "non-supported scheme does not match" {
    const input = "git://user:secret@github.com/foo/bar.git";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "case-insensitive scheme match" {
    const input = "POSTGRES://u:p@h/d";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("p", input[spans[0].start..spans[0].end]);
}

test "multiple URIs in one input" {
    const input =
        "A=postgres://u1:p1@h1/d1\n" ++
        "B=mysql://u2:p2pass@h2:3306/d2\n";
    const spans = try findPasswordSpans(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 2), spans.len);
    try std.testing.expectEqualStrings("p1", input[spans[0].start..spans[0].end]);
    try std.testing.expectEqualStrings("p2pass", input[spans[1].start..spans[1].end]);
}

test "round trip through engine.scan and Redactor produces expected output" {
    const engine = @import("engine.zig");
    const input = "DATABASE_URL=\"postgres://app_user:hunter2@db.local:5432/prod\"";
    const expected = "DATABASE_URL=\"postgres://app_user:[REDACTED:connection-string-password:1]@db.local:5432/prod\"";

    const hits = try engine.scan(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(hits);

    var r = engine.Redactor.init(std.testing.allocator);
    defer r.deinit();

    const out = try r.redact(input, hits);
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings(expected, out);
}
