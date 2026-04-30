const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const hook_script =
    \\#!/bin/sh
    \\# guard pre-commit hook — https://github.com/brueshi/guard
    \\git diff --staged | guard --summary >&2
    \\status=$?
    \\if [ $status -eq 1 ]; then
    \\    echo "" >&2
    \\    echo "commit blocked: guard detected secrets in staged changes" >&2
    \\    echo "remove the secrets, re-stage, and try again" >&2
    \\    echo "or bypass with: git commit --no-verify" >&2
    \\    exit 1
    \\fi
    \\exit 0
    \\
;

pub const InstallError = error{
    NotAGitRepo,
    GitInvocationFailed,
};

/// Public entry point: discover the git dir for the current working
/// directory and write the pre-commit hook there.
pub fn install(allocator: Allocator, io: Io) !void {
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buf);
    const sout = &stdout_writer.interface;

    const git_dir = try resolveGitDir(allocator, io, .inherit);
    defer allocator.free(git_dir);

    try installAt(allocator, io, .cwd(), git_dir);

    try sout.print("guard: pre-commit hook installed at {s}/hooks/pre-commit\n", .{git_dir});
    try sout.flush();
}

/// Resolve the path to the .git directory using `git rev-parse --git-dir`.
/// Caller owns the returned slice.
fn resolveGitDir(allocator: Allocator, io: Io, cwd: std.process.Child.Cwd) ![]u8 {
    var argv = [_][]const u8{ "git", "rev-parse", "--git-dir" };

    const result = std.process.run(allocator, io, .{
        .argv = &argv,
        .cwd = cwd,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.GitInvocationFailed,
        else => |e| return e,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return error.NotAGitRepo,
        else => return error.GitInvocationFailed,
    }

    const trimmed = std.mem.trimEnd(u8, result.stdout, "\r\n \t");
    if (trimmed.len == 0) return error.NotAGitRepo;
    return allocator.dupe(u8, trimmed);
}

/// Lower-level installer: write the hook into `<base>/<git_dir>/hooks/pre-commit`.
/// Used by the public install() and the tests (which substitute a tmp dir).
fn installAt(allocator: Allocator, io: Io, base: Io.Dir, git_dir: []const u8) !void {
    const hooks_rel = try std.fs.path.join(allocator, &.{ git_dir, "hooks" });
    defer allocator.free(hooks_rel);
    const hook_rel = try std.fs.path.join(allocator, &.{ hooks_rel, "pre-commit" });
    defer allocator.free(hook_rel);

    // Ensure the hooks directory exists. `git init` creates it, but be defensive.
    try base.createDirPath(io, hooks_rel);

    var file = try base.createFile(io, hook_rel, .{ .truncate = true });
    defer file.close(io);

    try file.writeStreamingAll(io, hook_script);
    try file.setPermissions(io, Io.File.Permissions.fromMode(0o755));
}

test "install writes executable pre-commit hook into a fresh git repo" {
    const testing = std.testing;
    const t_io = testing.io;
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Resolve the absolute path of the tmp dir so we can pass it as `cwd` to
    // `git init`, since std.process.Child needs an absolute path or a Dir.
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path_len = try tmp.dir.realPath(t_io, &path_buf);
    const tmp_path = path_buf[0..tmp_path_len];

    {
        var argv = [_][]const u8{ "git", "init", "-q" };
        const result = try std.process.run(allocator, t_io, .{
            .argv = &argv,
            .cwd = .{ .path = tmp_path },
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| try testing.expectEqual(@as(u8, 0), code),
            else => return error.GitInitFailed,
        }
    }

    // Resolve git-dir using the tmp_path as cwd, then install relative to tmp.dir.
    const git_dir = try resolveGitDir(allocator, t_io, .{ .path = tmp_path });
    defer allocator.free(git_dir);

    try installAt(allocator, t_io, tmp.dir, git_dir);

    // Verify file exists and contains the expected pipeline.
    const hook_rel = try std.fs.path.join(allocator, &.{ git_dir, "hooks", "pre-commit" });
    defer allocator.free(hook_rel);

    const contents = try tmp.dir.readFileAlloc(t_io, allocator, hook_rel, .unlimited);
    defer allocator.free(contents);
    try testing.expect(std.mem.indexOf(u8, contents, "guard --summary") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "git diff --staged") != null);

    // Verify executable bits are set (any of u/g/o execute).
    const stat = try tmp.dir.statFile(t_io, hook_rel, .{});
    if (Io.File.Permissions.has_executable_bit) {
        const mode = stat.permissions.toMode();
        try testing.expect(mode & 0o111 != 0);
    }
}
