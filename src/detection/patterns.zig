const std = @import("std");

pub const Charset = enum {
    base62,
    base64url,
    base64url_dot,
    hex_lower,
    base32,

    pub fn contains(c: Charset, ch: u8) bool {
        return switch (c) {
            .base62 => std.ascii.isAlphanumeric(ch),
            .base64url => std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-',
            .base64url_dot => std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.',
            .hex_lower => (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'),
            .base32 => (ch >= 'A' and ch <= 'Z') or (ch >= '2' and ch <= '7'),
        };
    }
};

pub const Pattern = struct {
    name: []const u8,
    prefixes: []const []const u8,
    charset: Charset,
    min_len: usize,
    max_len: usize,
    min_dots: u8 = 0,
};

pub const registry = [_]Pattern{
    .{ .name = "anthropic-api-key",      .prefixes = &.{"sk-ant-"},                                   .charset = .base64url, .min_len = 80,  .max_len = 200 },
    .{ .name = "openai-api-key",         .prefixes = &.{"sk-proj-"},                                  .charset = .base64url, .min_len = 50,  .max_len = 200 },
    .{ .name = "google-api-key",         .prefixes = &.{"AIza"},                                      .charset = .base64url, .min_len = 39,  .max_len = 39  },
    .{ .name = "gcp-oauth-token",        .prefixes = &.{"ya29."},                                     .charset = .base64url, .min_len = 50,  .max_len = 250 },
    .{ .name = "huggingface-token",      .prefixes = &.{"hf_"},                                       .charset = .base62,    .min_len = 35,  .max_len = 50  },
    .{ .name = "github-pat",             .prefixes = &.{ "ghp_", "gho_", "ghs_", "ghu_" },            .charset = .base62,    .min_len = 40,  .max_len = 40  },
    .{ .name = "github-fine-pat",        .prefixes = &.{"github_pat_"},                               .charset = .base64url, .min_len = 80,  .max_len = 100 },
    .{ .name = "gitlab-pat",             .prefixes = &.{"glpat-"},                                    .charset = .base64url, .min_len = 26,  .max_len = 50  },
    .{ .name = "aws-access-key",         .prefixes = &.{ "AKIA", "ASIA" },                            .charset = .base32,    .min_len = 20,  .max_len = 20  },
    .{ .name = "digitalocean-pat",       .prefixes = &.{"dop_v1_"},                                   .charset = .hex_lower, .min_len = 64,  .max_len = 80  },
    .{ .name = "stripe-secret-key",      .prefixes = &.{ "sk_live_", "sk_test_", "rk_live_", "rk_test_" }, .charset = .base62, .min_len = 28, .max_len = 200 },
    .{ .name = "stripe-publishable-key", .prefixes = &.{ "pk_live_", "pk_test_" },                    .charset = .base62,    .min_len = 28,  .max_len = 200 },
    .{ .name = "stripe-webhook-secret",  .prefixes = &.{"whsec_"},                                    .charset = .base62,    .min_len = 38,  .max_len = 70  },
    .{ .name = "slack-token",            .prefixes = &.{ "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xapp-" }, .charset = .base64url, .min_len = 30, .max_len = 250 },
    .{ .name = "docker-hub-pat",         .prefixes = &.{"dckr_pat_"},                                 .charset = .base64url, .min_len = 30,  .max_len = 70  },
    .{ .name = "npm-token",              .prefixes = &.{"npm_"},                                      .charset = .base62,    .min_len = 30,  .max_len = 50  },
    .{ .name = "linear-api-key",         .prefixes = &.{"lin_api_"},                                  .charset = .base62,    .min_len = 40,  .max_len = 60  },
    .{ .name = "figma-token",            .prefixes = &.{"figd_"},                                     .charset = .base64url, .min_len = 38,  .max_len = 70  },
    .{ .name = "postman-api-key",        .prefixes = &.{"PMAK-"},                                     .charset = .base64url, .min_len = 40,  .max_len = 80  },
    .{ .name = "postman-collection-token", .prefixes = &.{"PMAT-"},                                   .charset = .base64url, .min_len = 40,  .max_len = 80  },
    .{ .name = "sentry-auth-token",      .prefixes = &.{"sntrys_"},                                   .charset = .base62,    .min_len = 70,  .max_len = 80  },
    .{ .name = "sentry-user-token",      .prefixes = &.{"sntryu_"},                                   .charset = .base62,    .min_len = 70,  .max_len = 80  },
    .{ .name = "sentry-oauth-token",     .prefixes = &.{"sntryo_"},                                   .charset = .base62,    .min_len = 70,  .max_len = 80  },
    .{ .name = "brave-api-key",          .prefixes = &.{"BSAI"},                                      .charset = .base64url, .min_len = 24,  .max_len = 50  },
    .{ .name = "tavily-api-key",         .prefixes = &.{"tvly-"},                                     .charset = .base64url, .min_len = 30,  .max_len = 45  },
    .{ .name = "heroku-api-key",         .prefixes = &.{"HRKU-"},                                     .charset = .base62,    .min_len = 32,  .max_len = 50  },
    .{ .name = "openai-service-account", .prefixes = &.{"sk-svcacct-"},                               .charset = .base64url, .min_len = 50,  .max_len = 200 },
    .{ .name = "atlassian-api-token",    .prefixes = &.{"ATATT"},                                     .charset = .base64url, .min_len = 190, .max_len = 250 },
    .{ .name = "jwt",                    .prefixes = &.{"eyJ"},                                       .charset = .base64url_dot, .min_len = 100, .max_len = 5000, .min_dots = 2 },
};

pub const Match = struct {
    pattern_index: usize,
    start: usize,
    end: usize,

    pub fn name(m: Match) []const u8 {
        return registry[m.pattern_index].name;
    }
};

pub fn matchAt(input: []const u8, pos: usize) ?Match {
    inline for (registry, 0..) |pat, idx| {
        for (pat.prefixes) |prefix| {
            if (pos + prefix.len <= input.len and
                std.mem.eql(u8, input[pos..][0..prefix.len], prefix))
            {
                var end = pos + prefix.len;
                var dots: u8 = 0;
                while (end < input.len and pat.charset.contains(input[end])) : (end += 1) {
                    if (input[end] == '.') dots +|= 1;
                }

                const total = end - pos;
                if (total >= pat.min_len and total <= pat.max_len and dots >= pat.min_dots) {
                    return .{ .pattern_index = idx, .start = pos, .end = end };
                }
            }
        }
    }
    return null;
}

test "anthropic key matches" {
    const input = "key=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-end";
    const m = matchAt(input, 4) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("anthropic-api-key", m.name());
}

test "github pat exact 40 chars" {
    const input = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try std.testing.expectEqual(@as(usize, 40), input.len);
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("github-pat", m.name());
}

test "aws akia exact 20 chars" {
    const input = "AKIAIOSFODNN7EXAMPLE";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("aws-access-key", m.name());
}

test "too short fails length check" {
    const input = "ghp_short";
    try std.testing.expect(matchAt(input, 0) == null);
}

test "no match on plain text" {
    try std.testing.expect(matchAt("just normal text here", 0) == null);
}

test "jwt with three segments matches" {
    const input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("jwt", m.name());
}

test "eyJ without enough dots does not match jwt" {
    const input = "eyJabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyz0123456789";
    try std.testing.expect(matchAt(input, 0) == null);
}

test "postman api key matches" {
    const input = "PMAK-1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEF";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("postman-api-key", m.name());
}

test "postman collection token matches" {
    const input = "PMAT-1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEF";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("postman-collection-token", m.name());
}

test "sentry auth token matches" {
    const input = "sntrys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("sentry-auth-token", m.name());
}

test "sentry user token matches" {
    const input = "sntryu_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("sentry-user-token", m.name());
}

test "sentry oauth token matches" {
    const input = "sntryo_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("sentry-oauth-token", m.name());
}

test "brave api key matches" {
    const input = "BSAI1234567890abcdefghijklmnopqrstuvwxyz";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("brave-api-key", m.name());
}

test "tavily api key matches" {
    const input = "tvly-1234567890ABCDEFabcdefghijKLMNO";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("tavily-api-key", m.name());
}

test "heroku api key matches" {
    const input = "HRKU-1234567890abcdefghijklmnopqrstuvwx";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("heroku-api-key", m.name());
}

test "openai service account matches" {
    const input = "sk-svcacct-1234567890abcdefghijklmnopqrstuvwxyz_-ABCDEFGHIJKLMNOPQRSTUV";
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("openai-service-account", m.name());
}

test "atlassian api token matches" {
    // Atlassian tokens are typically 192+ chars after the ATATT prefix
    const input = "ATATT3xFfGF0" ++ ("a" ** 200);
    const m = matchAt(input, 0) orelse return error.NoMatch;
    try std.testing.expectEqualStrings("atlassian-api-token", m.name());
}
