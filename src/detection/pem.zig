const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Span = struct {
    start: usize,
    end: usize,
    name: []const u8,
};

const begin_marker = "-----BEGIN ";
const end_marker = "-----END ";
const private_key_suffix = "PRIVATE KEY-----";

const TypeMap = struct {
    word: []const u8,
    name: []const u8,
};

/// Map the BEGIN-line type word to a stable hit name.
/// An empty type word means PKCS#8 (the spec form: "-----BEGIN PRIVATE KEY-----").
const type_map = [_]TypeMap{
    .{ .word = "OPENSSH", .name = "openssh-private-key" },
    .{ .word = "RSA", .name = "rsa-private-key" },
    .{ .word = "EC", .name = "ec-private-key" },
    .{ .word = "DSA", .name = "dsa-private-key" },
    .{ .word = "ENCRYPTED", .name = "encrypted-private-key" },
};

const pkcs8_name = "pkcs8-private-key";

/// Find the start of the line containing `pos`.
fn lineStart(input: []const u8, pos: usize) usize {
    var i = pos;
    while (i > 0 and input[i - 1] != '\n') : (i -= 1) {}
    return i;
}

/// Find the index of the next '\n' at or after `from`, or input.len if none.
fn lineEnd(input: []const u8, from: usize) usize {
    var i = from;
    while (i < input.len and input[i] != '\n') : (i += 1) {}
    return i;
}

/// Trim trailing CR/space/tab from a line slice.
fn rtrimLine(line: []const u8) []const u8 {
    var n = line.len;
    while (n > 0) {
        const c = line[n - 1];
        if (c == ' ' or c == '\t' or c == '\r') {
            n -= 1;
        } else break;
    }
    return line[0..n];
}

/// Given a BEGIN line (without trailing whitespace/EOL), return the type word
/// or null if it's not a recognized "BEGIN ... PRIVATE KEY-----" line.
/// Returns empty string for PKCS#8 ("-----BEGIN PRIVATE KEY-----").
fn parseBeginLine(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, begin_marker)) return null;
    if (!std.mem.endsWith(u8, line, private_key_suffix)) return null;
    const body = line[begin_marker.len .. line.len - private_key_suffix.len];
    // body is either "" (PKCS#8) or "<TYPE> "
    if (body.len == 0) return body;
    if (body[body.len - 1] != ' ') return null;
    return body[0 .. body.len - 1];
}

/// Mirror of parseBeginLine for the END line.
fn parseEndLine(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, end_marker)) return null;
    if (!std.mem.endsWith(u8, line, private_key_suffix)) return null;
    const body = line[end_marker.len .. line.len - private_key_suffix.len];
    if (body.len == 0) return body;
    if (body[body.len - 1] != ' ') return null;
    return body[0 .. body.len - 1];
}

fn nameForType(type_word: []const u8) []const u8 {
    if (type_word.len == 0) return pkcs8_name;
    for (type_map) |m| {
        if (std.mem.eql(u8, m.word, type_word)) return m.name;
    }
    // Unknown but well-formed type — fall back to PKCS#8 label.
    return pkcs8_name;
}

/// Walk `input` and return every well-formed PEM private-key block found.
/// Tolerant of \r\n line endings and trailing whitespace on header/footer.
/// Blocks without a matching END line are skipped.
pub fn findBlocks(allocator: Allocator, input: []const u8) ![]Span {
    var spans: std.ArrayList(Span) = .empty;
    errdefer spans.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        // Find the next BEGIN marker.
        const idx = std.mem.indexOfPos(u8, input, i, begin_marker) orelse break;

        // Snap to the start of that line — only treat it as a header if the
        // marker actually starts the line (modulo leading whitespace would be
        // out-of-spec, so we keep this strict).
        const ls = lineStart(input, idx);
        if (ls != idx) {
            i = idx + begin_marker.len;
            continue;
        }

        const le = lineEnd(input, idx);
        const begin_line = rtrimLine(input[ls..le]);
        const begin_type = parseBeginLine(begin_line) orelse {
            i = idx + begin_marker.len;
            continue;
        };

        // Search for the matching END line.
        var search_from = le;
        const block_end = blk: {
            while (search_from < input.len) {
                const e_idx = std.mem.indexOfPos(u8, input, search_from, end_marker) orelse break :blk null;
                const e_ls = lineStart(input, e_idx);
                if (e_ls != e_idx) {
                    search_from = e_idx + end_marker.len;
                    continue;
                }
                const e_le = lineEnd(input, e_idx);
                const end_line = rtrimLine(input[e_ls..e_le]);
                if (parseEndLine(end_line)) |end_type| {
                    // Match if both are PKCS#8 (empty) or same word; tolerate
                    // any mismatch by still consuming up to this END to avoid
                    // an unbounded skip — but only emit when types match.
                    if (std.mem.eql(u8, end_type, begin_type)) {
                        break :blk e_le;
                    }
                }
                search_from = e_le;
            }
            break :blk null;
        };

        if (block_end) |be| {
            try spans.append(allocator, .{
                .start = ls,
                .end = be,
                .name = nameForType(begin_type),
            });
            i = be;
        } else {
            // No matching END; advance past this BEGIN to avoid getting stuck.
            i = le;
        }
    }

    return try spans.toOwnedSlice(allocator);
}

// ---------- tests ----------

test "clean RSA PEM block is detected" {
    const input =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n" ++
        "hijklmnop1234567890qrstuvwxyz\n" ++
        "-----END RSA PRIVATE KEY-----\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("rsa-private-key", spans[0].name);
    try std.testing.expectEqual(@as(usize, 0), spans[0].start);
    // end should land just past the END footer's newline-or-EOF.
    try std.testing.expect(spans[0].end <= input.len);
    try std.testing.expect(std.mem.startsWith(u8, input[spans[0].start..spans[0].end], "-----BEGIN RSA PRIVATE KEY-----"));
    try std.testing.expect(std.mem.endsWith(
        u8,
        std.mem.trimRight(u8, input[spans[0].start..spans[0].end], "\r\n"),
        "-----END RSA PRIVATE KEY-----",
    ));
}

test "OPENSSH and EC types map to correct names" {
    const input =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy\n" ++
        "-----END OPENSSH PRIVATE KEY-----\n" ++
        "junk in between\n" ++
        "-----BEGIN EC PRIVATE KEY-----\n" ++
        "MHcCAQEEIA==\n" ++
        "-----END EC PRIVATE KEY-----\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 2), spans.len);
    try std.testing.expectEqualStrings("openssh-private-key", spans[0].name);
    try std.testing.expectEqualStrings("ec-private-key", spans[1].name);
}

test "PKCS#8 (no type word) maps to pkcs8-private-key" {
    const input =
        "-----BEGIN PRIVATE KEY-----\n" ++
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n" ++
        "-----END PRIVATE KEY-----\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("pkcs8-private-key", spans[0].name);
}

test "DSA and ENCRYPTED types are recognized" {
    const input =
        "-----BEGIN DSA PRIVATE KEY-----\n" ++
        "AAA\n" ++
        "-----END DSA PRIVATE KEY-----\n" ++
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" ++
        "BBB\n" ++
        "-----END ENCRYPTED PRIVATE KEY-----\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 2), spans.len);
    try std.testing.expectEqualStrings("dsa-private-key", spans[0].name);
    try std.testing.expectEqualStrings("encrypted-private-key", spans[1].name);
}

test "trailing whitespace on header and footer still match" {
    const input =
        "-----BEGIN RSA PRIVATE KEY-----   \r\n" ++
        "MIIEpAIBAAKCAQEA\r\n" ++
        "-----END RSA PRIVATE KEY----- \t\r\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 1), spans.len);
    try std.testing.expectEqualStrings("rsa-private-key", spans[0].name);
}

test "text with no PEM block returns no spans" {
    const input = "the quick brown fox\nfn add(a: i32, b: i32) i32 { return a + b; }\n";
    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "BEGIN without matching END is skipped" {
    const input =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA\n" ++
        "(no END line here)\n";
    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);
    try std.testing.expectEqual(@as(usize, 0), spans.len);
}

test "multiple blocks are returned in order" {
    const input =
        "prefix\n" ++
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "AAA\n" ++
        "-----END RSA PRIVATE KEY-----\n" ++
        "middle\n" ++
        "-----BEGIN PRIVATE KEY-----\n" ++
        "BBB\n" ++
        "-----END PRIVATE KEY-----\n" ++
        "suffix\n";

    const spans = try findBlocks(std.testing.allocator, input);
    defer std.testing.allocator.free(spans);

    try std.testing.expectEqual(@as(usize, 2), spans.len);
    try std.testing.expect(spans[0].start < spans[1].start);
    try std.testing.expectEqualStrings("rsa-private-key", spans[0].name);
    try std.testing.expectEqualStrings("pkcs8-private-key", spans[1].name);
}
