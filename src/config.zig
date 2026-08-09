const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Paths whose contents are generated and whose high-entropy content is
/// never a credential. These dominate the false-positive count in real
/// repositories: an integrity-hash lockfile can produce several hundred
/// hits on its own, which is enough noise to make a pre-commit hook
/// unusable.
pub const default_ignores = [_][]const u8{
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",   "bun.lock",
    "bun.lockb",         "Cargo.lock",     "composer.lock", "Gemfile.lock",
    "poetry.lock",       "go.sum",         "*.min.js",    "*.min.css",
    "*.map",             "**/node_modules/**", "**/dist/**", "**/build/**",
    "**/.build/**",      "**/vendor/**",   "**/target/**", "**/zig-out/**",
    "**/*.dSYM/**",      "**/__snapshots__/**",
};

pub const Config = struct {
    /// Glob patterns matched against diff paths.
    ignores: std.ArrayList([]const u8) = .empty,
    /// Substrings that drop any hit containing them.
    allows: std.ArrayList([]const u8) = .empty,
    /// Backing storage for every slice above.
    text: ?[]u8 = null,

    pub fn deinit(c: *Config, allocator: Allocator) void {
        c.ignores.deinit(allocator);
        c.allows.deinit(allocator);
        if (c.text) |t| allocator.free(t);
    }

    pub fn matchesIgnored(c: Config, path: []const u8) bool {
        for (default_ignores) |p| if (globMatch(p, path)) return true;
        for (c.ignores.items) |p| if (globMatch(p, path)) return true;
        return false;
    }
};

/// Parse `.guardignore`. One directive per line:
///
///   # comment
///   pnpm-lock.yaml           path glob, matched against diff paths
///   **/generated/**
///   allow:AKIAIOSFODNN7EXAMPLE   substring that drops a hit
///
/// Line-based on purpose: the whole config surface is two lists, and a TOML
/// or YAML parser would be a dependency (or a few hundred lines) bought for
/// nothing.
pub fn parse(allocator: Allocator, text: []u8) !Config {
    var cfg = Config{ .text = text };
    errdefer cfg.deinit(allocator);

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.startsWith(u8, line, "allow:")) {
            const v = std.mem.trim(u8, line["allow:".len..], " \t");
            if (v.len > 0) try cfg.allows.append(allocator, v);
        } else {
            try cfg.ignores.append(allocator, line);
        }
    }
    return cfg;
}

/// Read `.guardignore` from `dir`, or from the nearest parent that has one.
/// Returns an empty config when there is none.
pub fn load(allocator: Allocator, io: Io, dir: Io.Dir) !Config {
    var rel: std.ArrayList(u8) = .empty;
    defer rel.deinit(allocator);

    // Walk up at most this far; enough for any real checkout, and bounded so
    // a detached or looping mount cannot spin here.
    const max_levels = 24;
    var level: usize = 0;
    while (level < max_levels) : (level += 1) {
        const path = try std.fmt.allocPrint(allocator, "{s}.guardignore", .{rel.items});
        defer allocator.free(path);

        if (dir.readFileAlloc(io, path, allocator, .limited(1 << 20))) |text| {
            return parse(allocator, text);
        } else |err| switch (err) {
            error.FileNotFound, error.NotDir => {},
            else => return err,
        }
        try rel.appendSlice(allocator, "../");
    }
    return Config{};
}

/// gitignore-flavoured glob. `*` matches within a path segment, `**` spans
/// segments, `?` matches one character. A pattern containing no `/` is
/// matched against the basename too, so `*.min.js` catches nested files.
pub fn globMatch(pattern: []const u8, path: []const u8) bool {
    if (matchHere(pattern, path)) return true;
    if (std.mem.indexOfScalar(u8, pattern, '/') == null) {
        const base = std.fs.path.basename(path);
        if (base.len != path.len and matchHere(pattern, base)) return true;
    }
    return false;
}

/// Recursive rather than iterative: a pattern like `**/*.dSYM/**` needs two
/// independent backtrack points live at once (the `**` and the `*`), and a
/// single saved position cannot express that.
fn matchHere(pattern: []const u8, path: []const u8) bool {
    if (pattern.len == 0) return path.len == 0;

    if (pattern[0] == '*') {
        if (pattern.len > 1 and pattern[1] == '*') {
            const rest = pattern[2..];
            // `**/x` matches `x` with no intervening segments at all.
            if (rest.len > 0 and rest[0] == '/' and matchHere(rest[1..], path)) return true;
            var i: usize = 0;
            while (true) : (i += 1) {
                if (matchHere(rest, path[i..])) return true;
                if (i >= path.len) return false;
            }
        }
        var i: usize = 0;
        while (true) : (i += 1) {
            if (matchHere(pattern[1..], path[i..])) return true;
            // A single star never spans a segment boundary.
            if (i >= path.len or path[i] == '/') return false;
        }
    }

    if (path.len == 0) return false;
    if (pattern[0] == '?' or pattern[0] == path[0]) return matchHere(pattern[1..], path[1..]);
    return false;
}

test "literal and basename matching" {
    try std.testing.expect(globMatch("package-lock.json", "package-lock.json"));
    try std.testing.expect(globMatch("package-lock.json", "web/package-lock.json"));
    try std.testing.expect(!globMatch("package-lock.json", "package.json"));
}

test "single star stays inside a segment" {
    try std.testing.expect(globMatch("*.min.js", "app.min.js"));
    try std.testing.expect(globMatch("*.min.js", "assets/app.min.js"));
    try std.testing.expect(!globMatch("src/*.js", "src/nested/app.js"));
}

test "double star spans segments" {
    try std.testing.expect(globMatch("**/dist/**", "packages/web/dist/assets/index.js"));
    try std.testing.expect(globMatch("**/dist/**", "dist/index.js"));
    try std.testing.expect(!globMatch("**/dist/**", "packages/web/src/index.js"));
}

test "dSYM directories match" {
    try std.testing.expect(globMatch("**/*.dSYM/**", "Core/.build/debug/Tests.dSYM/Contents/Info.plist"));
}

test "default ignores cover the measured offenders" {
    const cfg = Config{};
    try std.testing.expect(cfg.matchesIgnored("pnpm-lock.yaml"));
    try std.testing.expect(cfg.matchesIgnored("apps/api/go.sum"));
    try std.testing.expect(cfg.matchesIgnored("out/renderer/assets/ts.worker-D6bfeQIp.js.map"));
    try std.testing.expect(!cfg.matchesIgnored("src/detection/engine.zig"));
}

test "parse splits globs from allow directives" {
    const text = try std.testing.allocator.dupe(u8,
        \\# generated
        \\**/generated/**
        \\allow:AKIAIOSFODNN7EXAMPLE
        \\
    );
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.ignores.items.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.allows.items.len);
    try std.testing.expectEqualStrings("AKIAIOSFODNN7EXAMPLE", cfg.allows.items[0]);
    try std.testing.expect(cfg.matchesIgnored("src/generated/api.ts"));
}
