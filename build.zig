const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("pkg-config", "pkg-config.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    {
        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run pkgconfig");
        run_step.dependOn(&run_cmd.step);
    }

    const test_step = b.step("test", "Test pkgconfig");
    for (test_cases) |*case| {
        const run_step = exe.run();
        run_step.stdout_action = case.expect_stdout.toAction();
        run_step.stderr_action = case.expect_stderr.toAction();
        run_step.expected_exit_code = if (case.fail) 1 else 0;
        if (case.include_testpkgs) {
            run_step.setEnvironmentVariable("PKG_CONFIG_PATH", b.pathFromRoot("testpkgs"));
        } else {
            run_step.getEnvMap().remove("PKG_CONFIG_PATH");
        }
        run_step.addArgs(case.args);
        test_step.dependOn(&run_step.step);
    }

    {
        const run_cmd = b.addSystemCommand(&.{"pkg-config"});
        run_cmd.expected_exit_code = null;
        run_cmd.setEnvironmentVariable("PKG_CONFIG_PATH", b.pathFromRoot("testpkgs"));
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        const run_step = b.step("system-pkg-config", "Run system pkg-config with our packages");
        run_step.dependOn(&run_cmd.step);
    }
}

const ExpectOut = union(enum) {
    exact: []const u8,
    matches: []const []const u8,
    pub fn toAction(self: ExpectOut) std.build.RunStep.StdIoAction {
        return switch (self) {
            .exact => |exact| .{ .expect_exact = exact },
            .matches => |matches| .{ .expect_matches = matches },
        };
    }
};

const TestCase = struct {
    fail: bool,
    expect_stdout: ExpectOut,
    expect_stderr: ExpectOut,
    args: []const []const u8,
    include_testpkgs: bool = true,
};

const CommonOpt = struct {
    include_testpkgs: bool = true,
};
fn failCase(expect_stdout: []const u8, expect_stderr: []const u8, args: []const []const u8, opt: CommonOpt) TestCase {
    return .{ .fail = true, .expect_stdout = .{ .exact = expect_stdout}, .expect_stderr = .{ .exact = expect_stderr}, .args = args, .include_testpkgs = opt.include_testpkgs };
}
fn goodCase(expect_stdout: []const u8, expect_stderr: []const u8, args: []const []const u8, opt: CommonOpt) TestCase {
    return .{ .fail = false, .expect_stdout = .{ .exact = expect_stdout}, .expect_stderr = .{ .exact = expect_stderr}, .args = args, .include_testpkgs = opt.include_testpkgs };
}

const test_cases = [_]TestCase{
    failCase("Must specify package names on the command line\n", "", &.{}, .{}),
    goodCase("0.29.1\n", "", &.{"--version"}, .{}),
    failCase("Unknown option --badoption\n", "", &.{"--badoption"}, .{}),
    goodCase("", "", &.{"--exists", "this-is-a-specific-test-pkg"}, .{}),
    failCase("", "", &.{"--exists", "this-is-a-specific-test-pkg"}, .{ .include_testpkgs = false }),
    failCase("", "error: '--exists' is incompatible with '--modversion'\n",
             &.{"--modversion", "--exists", "this-is-a-specific-test-pkg"}, .{}),
    failCase("", "error: '--modversion' is incompatible with '--exists'\n",
             &.{"--exists", "--modversion", "this-is-a-specific-test-pkg"}, .{}),
    failCase("", "No package 'blah' found\n", &.{"--modversion", "blah"}, .{}),
    goodCase("1.2.3\n", "", &.{"--modversion", "foo"}, .{}),
    failCase("", "Package 'missing-version' has no Version: field\n", &.{"--modversion", "missing-version"}, .{}),

    goodCase("/usr\n", "", &.{"--variable=prefix", "some-vars"}, .{}),
    goodCase("\n", "", &.{"--variable=this_var_does_not_exist", "some-vars"}, .{}),

    .{ .fail = true, .expect_stdout = .{ .exact = "" }, .expect_stderr = .{ .matches = &.{
        "Variable 'version' not defined in '", "pkgs/missing-var.pc'",
    } }, .args = &.{"--modversion", "missing-var"} },

    goodCase("9.8.7\n", "", &.{"--modversion", "var-subs"}, .{}),

    goodCase("-I/usr/include/foo-1.2.3 -Dlibfoo_linux\n", "", &.{"--cflags", "foo"}, .{}),
    goodCase("-I/usr/include/foo-1.2.3\n", "", &.{"--cflags-only-I", "foo"}, .{}),
    goodCase("-Dlibfoo_linux\n", "", &.{"--cflags-only-other", "foo"}, .{}),
    goodCase("-L/usr/lib/foo-1.2.3 -lfoo1 --other-linker-flag\n", "", &.{"--libs", "foo"}, .{}),
    goodCase("-L/usr/lib/foo-1.2.3\n", "", &.{"--libs-only-L", "foo"}, .{}),
    goodCase("-lfoo1\n", "", &.{"--libs-only-l", "foo"}, .{}),
    goodCase("--other-linker-flag\n", "", &.{"--libs-only-other", "foo"}, .{}),
};
