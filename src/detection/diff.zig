const std = @import("std");
const config = @import("../config.zig");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;

pub const Range = engine.CoveredRange;

const section_marker = "diff --git ";

/// True when the input looks like `git diff` output. Path filtering only
/// applies to diffs, because that is the only form where guard can tell
/// which file a byte belongs to.
pub fn looksLikeDiff(input: []const u8) bool {
    if (std.mem.startsWith(u8, input, section_marker)) return true;
    var needle: [section_marker.len + 1]u8 = undefined;
    needle[0] = '\n';
    @memcpy(needle[1..], section_marker);
    return std.mem.indexOf(u8, input, &needle) != null;
}

fn lineEnd(input: []const u8, from: usize) usize {
    return std.mem.indexOfScalarPos(u8, input, from, '\n') orelse input.len;
}

/// Extract the post-image path from a `diff --git a/x b/y` header.
/// Returns the `b/` side with its prefix stripped, since that is the path
/// the change lands at.
fn pathFromHeader(line: []const u8) ?[]const u8 {
    const rest = line[section_marker.len..];
    // Quoted paths (those with spaces or non-ASCII) are rare; skipping them
    // means we scan the hunk rather than silently ignoring it.
    if (rest.len == 0 or rest[0] == '"') return null;
    const b_at = std.mem.lastIndexOf(u8, rest, " b/") orelse return null;
    return rest[b_at + 3 ..];
}

/// Byte ranges belonging to files the config wants ignored. The engine skips
/// hits that start inside one of these.
pub fn ignoredRanges(allocator: Allocator, input: []const u8, cfg: config.Config) ![]Range {
    var out: std.ArrayList(Range) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    var open: ?Range = null;

    while (i < input.len) {
        const e = lineEnd(input, i);
        if (std.mem.startsWith(u8, input[i..e], section_marker)) {
            if (open) |*r| {
                r.end = i;
                try out.append(allocator, r.*);
                open = null;
            }
            if (pathFromHeader(input[i..e])) |path| {
                if (cfg.matchesIgnored(path)) open = .{ .start = i, .end = input.len };
            }
        }
        i = e + 1;
    }
    if (open) |r| try out.append(allocator, r);

    return try out.toOwnedSlice(allocator);
}

test "detects git diff input" {
    try std.testing.expect(looksLikeDiff("diff --git a/x b/x\n"));
    try std.testing.expect(looksLikeDiff("commit abc\n\ndiff --git a/x b/x\n"));
    try std.testing.expect(!looksLikeDiff("just some code\n"));
}

test "lockfile section is ignored and source section is not" {
    const input =
        "diff --git a/pnpm-lock.yaml b/pnpm-lock.yaml\n" ++
        "--- a/pnpm-lock.yaml\n+++ b/pnpm-lock.yaml\n" ++
        "+  integrity: sha512-AAAA\n" ++
        "diff --git a/src/app.ts b/src/app.ts\n" ++
        "+const x = 1;\n";

    const cfg = config.Config{};
    const ranges = try ignoredRanges(std.testing.allocator, input, cfg);
    defer std.testing.allocator.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    const covered = input[ranges[0].start..ranges[0].end];
    try std.testing.expect(std.mem.indexOf(u8, covered, "pnpm-lock") != null);
    try std.testing.expect(std.mem.indexOf(u8, covered, "src/app.ts") == null);
}

test "trailing ignored section runs to end of input" {
    const input =
        "diff --git a/src/app.ts b/src/app.ts\n+const x = 1;\n" ++
        "diff --git a/go.sum b/go.sum\n+h1:AAAA\n";

    const cfg = config.Config{};
    const ranges = try ignoredRanges(std.testing.allocator, input, cfg);
    defer std.testing.allocator.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    try std.testing.expectEqual(input.len, ranges[0].end);
}

test "no ignored paths yields no ranges" {
    const input = "diff --git a/src/app.ts b/src/app.ts\n+const x = 1;\n";
    const cfg = config.Config{};
    const ranges = try ignoredRanges(std.testing.allocator, input, cfg);
    defer std.testing.allocator.free(ranges);
    try std.testing.expectEqual(@as(usize, 0), ranges.len);
}

test "renamed file uses the destination path" {
    const input = "diff --git a/src/a.ts b/dist/a.js\n+x\n";
    const cfg = config.Config{};
    const ranges = try ignoredRanges(std.testing.allocator, input, cfg);
    defer std.testing.allocator.free(ranges);
    try std.testing.expectEqual(@as(usize, 1), ranges.len);
}
