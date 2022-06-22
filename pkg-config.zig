const std = @import("std");

const version = "0.29.1";

pub const log_level: std.log.Level = .warn;

// TODO: not sure if I need the +1 for the terminating 0 or not
const path_buf_len = std.fs.MAX_PATH_BYTES + 1;

const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

pub const Flag = enum {
    cflags_I,
    cflags_other,
    libs_l,
    libs_L,
    libs_other,
    static,

    pub const Bits = u16;
    pub const cflags_all_mask: Bits = Flag.cflags_I.bit() | Flag.cflags_other.bit();
    pub const libs_all_mask: Bits = Flag.libs_l.bit() | Flag.libs_L.bit() | Flag.libs_other.bit();
    pub fn bit(self: Flag) u16 {
        return @as(u16, 1) << @enumToInt(self);
    }
};

const MainOp = union(enum) {
    exists: void,
    modversion: void,
    variable: []const u8,
    flags: struct {
        first_opt: []const u8,
        bits: Flag.Bits,
    },
    pub fn getOptionString(self: MainOp) []const u8 {
        return switch (self) {
            .exists => "--exists",
            .modversion => "--modversion",
            .variable => "--variable",
            .flags => |flags| return flags.first_opt,
        };
    }

    pub const State = union(enum) {
        none: void,
        args: struct {
            arena: std.heap.ArenaAllocator,
            cflags: std.ArrayListUnmanaged([]const u8) = .{},
            libs: std.ArrayListUnmanaged([]const u8) = .{},
            pub fn addCflag(self: *@This(), cflag: []const u8) void {
                // todo: check if this library is a system path that would
                //       already be added

                // check if it's already added
                for (self.cflags.items) |existing| {
                    if (std.mem.eql(u8, existing, cflag)) {
                        std.log.debug("compilation flag '{s}' already added", .{cflag});
                        return;
                    }
                }
                const cflag_copy = self.arena.allocator().dupe(u8, cflag) catch |e| oom(e);
                errdefer self.arena.free(cflag_copy);
                self.cflags.append(self.arena.allocator(), cflag_copy) catch |e| oom(e);
            }
            pub fn addLib(self: *@This(), lib: []const u8) void {
                // todo: check if this library is a system path that would
                //       already be added

                // check if it's already added
                for (self.libs.items) |existing| {
                    if (std.mem.eql(u8, existing, lib)) {
                        std.log.debug("library flag '{s}' already added", .{lib});
                        return;
                    }
                }
                const lib_copy = self.arena.allocator().dupe(u8, lib) catch |e| oom(e);
                errdefer self.arena.free(lib_copy);
                self.libs.append(self.arena.allocator(), lib_copy) catch |e| oom(e);
            }
            pub fn printFlags(self: @This()) !void {
                var buffered = std.io.BufferedWriter(std.mem.page_size, @TypeOf(stdout)) {
                    .unbuffered_writer = stdout,
                };
                var prefix: []const u8 = "";
                for (self.cflags.items) |arg| {
                    try buffered.writer().print("{s}{s}", .{prefix, arg});
                    prefix = " ";
                }
                for (self.libs.items) |arg| {
                    try buffered.writer().print("{s}{s}", .{prefix, arg});
                    prefix = " ";
                }
                try buffered.writer().writeAll("\n");
                try buffered.flush();
            }
        },
        pub fn addCflag(self: *State, cflag: []const u8) void {
            switch (self.*) {
                .none => unreachable,
                .args => |*args| args.addCflag(cflag),
            }
        }
        pub fn addLib(self: *State, lib: []const u8) void {
            switch (self.*) {
                .none => unreachable,
                .args => |*args| args.addLib(lib),
            }
        }
        pub fn printFlags(self: State) !void {
            switch (self) {
                .none => unreachable,
                .args => |args| try args.printFlags(),
            }
        }
    };
    pub fn initState(self: MainOp) State {
        switch (self) {
            .exists => return .none,
            .modversion => return .none,
            .variable => return .none,
            .flags => return .{
                .args = .{
                    .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
                },
            },
        }
    }
};

pub fn main() !u8 {
    var options = struct {
        print_errors: bool = false,
        short_errors: bool = false,
        main_op: ?MainOp = null,
        fn setMainOp(self: *@This(), new_op: MainOp) void {
            if (self.main_op) |first| {
                if (std.meta.activeTag(first) == std.meta.activeTag(new_op)) {
                    std.log.err("'{s}' given twice?", .{first.getOptionString()});
                } else {
                    std.log.err("'{s}' is incompatible with '{s}'", .{new_op.getOptionString(), first.getOptionString()});
                }
                std.os.exit(1);
            }
            self.main_op = new_op;
        }
        pub fn setFlag(self: *@This(), arg: []const u8, flag: Flag) void {
            self.setFlagBits(arg, flag.bit());
        }
        pub fn setFlagBits(self: *@This(), arg: []const u8, bits: Flag.Bits) void {
            if (self.main_op) |*first| switch (first.*) {
                .flags => |*flags| {
                    flags.bits |= bits;
                },
                else => {
                    std.log.err("'{s}' is incompatible with '{s}'", .{arg, first.getOptionString()});
                    std.os.exit(1);
                },
            };
            self.main_op = .{ .flags = .{ .first_opt = arg, .bits = bits } };
        }
    }{ };
    var pkg_arg_count: usize = 0;
    var pkg_arg_ptr = std.os.argv.ptr + 1;
    {
        const variable_option_prefix = "--variable=";

        var arg_index: usize = 1;
        while (arg_index < std.os.argv.len) : (arg_index += 1) {
            const arg = std.mem.span(std.os.argv[arg_index]);
            if (!std.mem.startsWith(u8, arg, "-")) {
                pkg_arg_ptr[pkg_arg_count] = arg;
                pkg_arg_count += 1;
            } else if (std.mem.eql(u8, "--version", arg)) {
                try stdout.writeAll(version ++ "\n");
                return 0;
            } else if (std.mem.eql(u8, "--print-errors", arg)) {
                options.print_errors = true;
            } else if (std.mem.eql(u8, "--short-errors", arg)) {
                options.short_errors = true;
            } else if (std.mem.eql(u8, "--exists", arg)) {
                options.setMainOp(.exists);
            } else if (std.mem.eql(u8, "--modversion", arg)) {
                options.setMainOp(.modversion);
            } else if (std.mem.startsWith(u8, arg, variable_option_prefix)) {
                options.setMainOp(.{ .variable = arg[variable_option_prefix.len..] });
            } else if (std.mem.eql(u8, arg, "--cflags-only-I")) {
                options.setFlag(arg, .cflags_I);
            } else if (std.mem.eql(u8, arg, "--cflags-only-other")) {
                options.setFlag(arg, .cflags_other);
            } else if (std.mem.eql(u8, arg, "--cflags")) {
                options.setFlagBits(arg, Flag.cflags_all_mask);
            } else if (std.mem.eql(u8, arg, "--libs-only-l")) {
                options.setFlag(arg, .libs_l);
            } else if (std.mem.eql(u8, arg, "--libs-only-L")) {
                options.setFlag(arg, .libs_L);
            } else if (std.mem.eql(u8, arg, "--libs-only-other")) {
                options.setFlag(arg, .libs_other);
            } else if (std.mem.eql(u8, arg, "--libs")) {
                options.setFlagBits(arg, Flag.libs_all_mask);
            } else {
                try stdout.print("Unknown option {s}\n", .{arg});
                return 1;
            }
        }
    }

    if (pkg_arg_count == 0) {
        try stdout.writeAll("Must specify package names on the command line\n");
        return 1;
    }
    const pkgs_slice = pkg_arg_ptr[0 .. pkg_arg_count];

    const main_op = options.main_op orelse .exists;
    var main_op_state = main_op.initState();
    var exit_code: u8 = 0;

    for (pkgs_slice) |pkg_ptr| {
        const pkg = std.mem.span(pkg_ptr);

        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // TODO: handle if pkg contains a version check (i.e. foo >= 2.7)
        std.log.info("TODO: handle '{s}'", .{pkg});

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        switch (try handlePackage(arena.allocator(), main_op, &main_op_state, pkg)) {
            .ok => {},
            .non_zero_exit => exit_code = 1,
        }
    }

    switch (main_op) {
        .exists => {
            // exists should have exited before this if there was a pkg error
            std.debug.assert(exit_code == 0);
            return 0;
        },
        .modversion => return exit_code,
        .variable => return exit_code,
        // TODO: not sure if this is correct in the .flags case
        .flags => {
            if (exit_code != 0) return exit_code;
            try main_op_state.printFlags();
            return 0;
        }
    }
}

fn handlePackage(
    allocator: std.mem.Allocator,
    main_op: MainOp,
    main_op_state: *MainOp.State,
    pkg: []const u8,
) !enum { ok, non_zero_exit } {
    var pc_path_buf: [path_buf_len]u8 = undefined;
    const opt_pc_path: ?[:0]u8 = if (findPackage(&pc_path_buf, pkg)) |pc_path_len|
        pc_path_buf[0..pc_path_len :0] else null;
    if (opt_pc_path) |pc_path| {
        std.log.debug("found package '{s}' at '{s}'", .{pkg, pc_path});
    } else {
        std.log.debug("package '{s}' does not exist", .{pkg});
    }
    switch (main_op) {
        .exists => {
            if (opt_pc_path == null) return std.os.exit(1);
            return .ok;
        },
        .modversion => {
            const pc_path = opt_pc_path orelse {
                try informMissingPackage(pkg);
                return .non_zero_exit;
            };
            var parser = Parser {
                .allocator = allocator,
                .content = try readFile(allocator, pc_path),
            };
            defer parser.deinit();
            while (parser.next()) |line| {
                if (std.mem.eql(u8, line.keyword, "Version")) {
                    const sub = try stringSub(allocator, pc_path, &parser.var_map, line.raw_value);
                    defer sub.deinit(allocator);
                    try stdout.print("{s}\n", .{sub.value});
                    return .ok;
                }
            }

            try stderr.print("Package '{s}' has no Version: field\n", .{pkg});
            return .non_zero_exit;
        },
        .variable => |name| {
            const pc_path = opt_pc_path orelse {
                try informMissingPackage(pkg);
                return .non_zero_exit;
            };
            var parser = Parser {
                .allocator = allocator,
                .content = try readFile(allocator, pc_path),
            };
            defer parser.deinit();
            while (parser.next()) |_| {}
            // missing variable is apparently fine
            const raw_value = parser.var_map.getRaw(name) orelse "";
            const sub = try stringSub(allocator, pc_path, &parser.var_map, raw_value);
            defer sub.deinit(allocator);
            try stdout.print("{s}\n", .{sub.value});
            // DISCREPANCY: when pkg-config --variable=FOO does multiple packages, it will
            //              separate the values with a space character ' '.  This seems dumb
            //              though since values can have spaces so you wouldn't be able to
            //              tell where one value ends and the next begins.
            return .ok;
        },
        .flags => |flags| {
            const pc_path = opt_pc_path orelse {
                try informMissingPackage(pkg);
                return .non_zero_exit;
            };
            var parser = Parser {
                .allocator = allocator,
                .content = try readFile(allocator, pc_path),
            };
            defer parser.deinit();
            var raw_fields: struct {
                cflags: ?[]const u8 = null,
                libs: ?[]const u8 = null,
                libs_private: ?[]const u8 = null,
                requires: ?[]const u8 = null,
                // only include libs flags from Requires.private if compiling statically
                requires_private: ?[]const u8 = null,
            } = .{};
            while (parser.next()) |line| {
                if (std.mem.eql(u8, line.keyword, "Cflags")) {
                    raw_fields.cflags = line.raw_value;
                } else if (std.mem.eql(u8, line.keyword, "Libs")) {
                    raw_fields.libs = line.raw_value;
                } else if (std.mem.eql(u8, line.keyword, "Libs.private")) {
                    raw_fields.libs_private = line.raw_value;
                } else if (std.mem.eql(u8, line.keyword, "Requires")) {
                    raw_fields.requires = line.raw_value;
                } else if (std.mem.eql(u8, line.keyword, "Requires.private")) {
                    raw_fields.requires_private = line.raw_value;
                }
            }

            if (0 != (flags.bits & Flag.cflags_all_mask)) {
                if (raw_fields.cflags) |cflags| {
                    const sub = try stringSub(allocator, pc_path, &parser.var_map, cflags);
                    defer sub.deinit(allocator);
                    var it = std.mem.tokenize(u8, sub.value, &whitespace);
                    while (it.next()) |flag| {
                        const flag_type = getCflagType(flag);
                        if (0 == (flags.bits & flag_type.flag().bit())) {
                            std.log.debug("Cflag '{s}' (type={s}) not included", .{flag, @tagName(flag_type)});
                        } else {
                            main_op_state.addCflag(flag);
                        }
                    }
                }
                if (raw_fields.requires) |_| {
                    std.debug.panic("handle Requires in {s}: '{s}'", .{pc_path, raw_fields.requires});
                }
                if (raw_fields.requires_private) |_| {
                    @panic("TODO: handle Requires");
                }
            }
            if (0 != (flags.bits & Flag.libs_all_mask)) {
                // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                // TODO: filter out system library directories, (i.e. -L/usr/lib)
                if (raw_fields.libs) |libs| {
                    const sub = try stringSub(allocator, pc_path, &parser.var_map, libs);
                    defer sub.deinit(allocator);
                    var it = std.mem.tokenize(u8, sub.value, &whitespace);
                    while (it.next()) |flag| {
                        const flag_type = getLibFlagType(flag);
                        if (0 == (flags.bits & flag_type.flag().bit())) {
                            std.log.debug("Lib flag '{s}' (type={s}) not included", .{flag, @tagName(flag_type)});
                        } else {
                            main_op_state.addLib(flag);
                        }
                    }
                }
                if (raw_fields.libs_private) |_| {
                    @panic("TODO: handle Libs.private");
                }
                if (raw_fields.requires) |_| {
                    @panic("TODO: handle Requires");
                }
                if ((0 != (flags.bits & Flag.static.bit()))) {
                    if (raw_fields.requires_private) |_| {
                        @panic("TODO: handle --static and Requires.private");
                    }
                }
            }
            if (0 != (flags.bits & Flag.static.bit())) {
                @panic("TODO: handle --static");
            }
            return .ok;
        },
    }
}

const LibFlagType = enum {
    l, L, other,
    pub fn flag(self: LibFlagType) Flag {
        return switch (self) {
            .l => .libs_l,
            .L => .libs_L,
            .other => .libs_other,
        };
    }
};
fn getLibFlagType(flag: []const u8) LibFlagType {
    if (std.mem.startsWith(u8, flag, "-l")) return .l;
    if (std.mem.startsWith(u8, flag, "-L")) return .L;
    return .other;
}

const CflagType = enum {
    I, other,
    pub fn flag(self: CflagType) Flag {
        return switch (self) {
            .I => .cflags_I,
            .other => .cflags_other,
        };
    }
};
fn getCflagType(flag: []const u8) CflagType {
    if (std.mem.startsWith(u8, flag, "-I")) return .I;
    return .other;
}


// TODO: do I need t+1 here?
fn findPackage(out_path: *[path_buf_len]u8, name: []const u8) ?usize {
    std.log.debug("findPackage '{s}'", .{name});
    if (std.os.getenvZ("PKG_CONFIG_PATH")) |path| {
        std.log.info("checking PKG_CONFIG_PATH '{s}'", .{path});
        if (findPackageWithPath(out_path, name, path)) |len| return len;
    } else {
        std.log.info("no PKG_CONFIG_PATH to check", .{});
    }

    // from: https://linux.die.net/man/1/pkg-config
    // The default directory will always be searched after searching the path; the default is
    // libdir/pkgconfig:datadir/pkgconfig where libdir is the libdir where pkg-config [has been confingured?]
    // and datadir is the datadir where pkg-config was installed.
    const libdir = "/lib"; // just hardcode for now
    const datadir = "/data";
    // disable for testing until sysroot is implemented our testse work
    if (true) return null;
    return findPackageWithPath(out_path, name, libdir ++ ":" ++ datadir);
}

fn findPackageWithPath(out_path: *[path_buf_len]u8, name: []const u8, path: []const u8) ?usize {
    if (path.len == 0) return null;
    // TODO: should we reject relative paths?

    var it = std.mem.tokenize(u8, path, ":");
    while (it.next()) |search_path| {
        const len = (std.fmt.bufPrintZ(out_path, "{s}/{s}.pc", .{search_path, name}) catch |err| switch (err) {
            error.NoSpaceLeft => continue,
        }).len;
        std.fs.cwd().accessZ(std.meta.assumeSentinel(out_path, 0), .{}) catch {
            continue;
        };
        return len;
    }
    return null;
}

fn fatalInformMissingVariable(pc_filename: []const u8, name: []const u8) noreturn {
    stderr.print("Variable '{s}' not defined in '{s}'\n", .{name, pc_filename}) catch |err| {
        std.debug.panic("write to stderr to inform user of missing variable name '{s}' failed because of '{s}'", .{name, @errorName(err)});
    };
    std.os.exit(1);
}
fn informMissingPackage(pkg: []const u8) !void {
    try stderr.print(
// This explanation seems a bit excessive to me
//        "Package {s} was not found in the pkg-config search path.\n" ++
//            "Perhaps you should add the directory containing `{0s}'\n" ++
//            "to the PKG_CONFIG_PATH environment variable\n" ++
            "No package '{0s}' found\n",
        .{pkg},
    );
}

fn readFile(allocator: std.mem.Allocator, filename: []const u8) ![]const u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, std.math.maxInt(usize));
}

fn oom(err: anytype) noreturn { switch (err) { error.OutOfMemory => @panic("Out of memory") } }

const SubMap = struct {
    const Entry = struct {
        raw: []const u8,
        subbed: ?StringSub,
    };
    map: std.StringHashMapUnmanaged(Entry) = .{},
    pub fn deinit(self: *SubMap, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.subbed) |*s| s.deinit(allocator);
        }
        self.map.deinit(allocator);
    }
    pub fn put(self: *SubMap, allocator: std.mem.Allocator, name: []const u8, raw_value: []const u8) error{OutOfMemory}!void {
        try self.map.put(allocator, name, .{ .raw = raw_value, .subbed = null });
    }
    pub fn getRaw(self: SubMap, name: []const u8) ?[]const u8 {
        return if (self.map.get(name)) |*entry| entry.raw else null;
    }
    pub fn getSubbed(self: *SubMap, allocator: std.mem.Allocator, filename_for_error: []const u8, name: []const u8) ![]const u8 {
        const value_ptr = self.map.getPtr(name) orelse fatalInformMissingVariable(filename_for_error, name);
        if (value_ptr.subbed == null) {
            value_ptr.subbed = try stringSub(allocator, filename_for_error, self, value_ptr.raw);
        }
        return value_ptr.subbed.?.value;
    }
};

const Parser = struct {
    allocator: std.mem.Allocator,
    content: []const u8,
    next_offset: usize = 0,
    var_map: SubMap = .{},//std.StringHashMapUnmanaged([]const u8) = .{},

    pub fn deinit(self: *Parser) void {
        self.var_map.deinit(self.allocator);
    }
    pub const Line = struct {
        keyword: []const u8,
        raw_value: []const u8,
    };
    pub fn next(self: *Parser) ?Line {
        while (true) {
            std.log.info("next offset={}", .{self.next_offset});
            const offset = scanWhitespace(self.content, self.next_offset);
            std.log.info("    next offset={}", .{offset});
            if (offset >= self.content.len) return null;

            const line_start = offset;
            const line_end = scanTo(self.content, line_start, '\n');
            self.next_offset = line_end;

            var line = self.content[line_start..line_end];
            line.len = std.mem.indexOfScalar(u8, line, '#') orelse line.len;
            line.len = std.mem.trimRight(u8, line, &whitespace).len;
            if (line.len == 0) continue;

            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            // TODO: it looks like pkg-config makes some restrictuions on what can appear
            //       before the '=' sign in a variable assignment (i.e. no '-' character).
            //       I'm guessing they scan the line while they have valid variable name characters
            //       or until they see an '=', which would determine whether it's a variable assignment.
            const eq_index = std.mem.indexOfScalar(u8, line, '=') orelse line.len;
            const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse line.len;
            if (eq_index < colon_index) {
                std.debug.assert(eq_index < line.len); // this would be a simple logic bug
                const varname = std.mem.trimRight(u8, line[0 .. eq_index], &whitespace);
                //for (varname) |c| {
                //    if (!isValidVarnameChar(c)) {
                //        std.log.err("variable '{s}' contains invalid char '{c}' (0x{x}) (TODO: what to do here?)", .{varname, c, c});
                //        os.exit(0xff);
                //    }
                //}
                //if (std.mem.indexOfScalar(u8, varname,
                const raw_value = removeInlineComment(std.mem.trimLeft(u8, line[eq_index + 1 ..], &whitespace));
                self.var_map.put(self.allocator, varname, raw_value) catch |e| oom(e);
            } else if (colon_index < line.len) {
                return Line{
                    .keyword = std.mem.trimRight(u8, line[0 .. colon_index], &whitespace),
                    .raw_value = removeInlineComment(std.mem.trimLeft(u8, line[colon_index + 1 ..], &whitespace)),
                };
            } else {
                @panic("TODO: line with neither '=' nor ':'");
            }
        }
    }
};

fn removeInlineComment(line: []const u8) []const u8 {
    const hash_index = std.mem.indexOfScalar(u8, line, '#') orelse line.len;
    return line[0 .. hash_index];
}

const whitespace = [_]u8 { ' ', '\n', '\t', '\r' };

fn isWhitespace(c: u8) bool {
    inline for (whitespace) |ws| {
        if (c == ws) return true;
    }
    return false;
}
fn scanWhitespace(text: []const u8, start: usize) usize {
    var offset : usize = start;
    while (offset < text.len) : (offset += 1) {
        if (!isWhitespace(text[offset])) break;
    }
    return offset;
}
fn scanTo(text: []const u8, start: usize, to: u8) usize {
    var offset : usize = start;
    while (offset < text.len) : (offset += 1) {
        if (text[offset] == to) break;
    }
    return offset;
}

pub const StringSub = struct {
    value: []const u8,
    sub_performed: bool,
    pub fn deinit(self: StringSub, allocator: std.mem.Allocator) void {
        if (self.sub_performed) {
            allocator.free(self.value);
        }
    }
};
fn stringSub(
    allocator: std.mem.Allocator,
    filename_for_error: []const u8,
    var_map: *SubMap,
    raw_str: []const u8,
) error{OutOfMemory}!StringSub {
    var result = StringSub{
        .value = raw_str,
        .sub_performed = false,
    };
    errdefer result.deinit(allocator);
    while (true) {
        const dollar_index = std.mem.indexOfScalar(u8, result.value, '$') orelse return result;
        const before = result.value[0 .. dollar_index];
        const rest = result.value[dollar_index + 1..];
        if (rest.len == 0) {
            std.log.err("string cannot end with '$': '{s}'", .{result.value});
            std.os.exit(0xff);
        }

        if (rest[0] == '$') {
            @panic("TODO");
        } else if (rest[0] == '{') {
            const end = 1 + (std.mem.indexOfScalar(u8, rest[1..], '}') orelse {
                std.log.err("substitution '${{...' is missing the closing '}}': '{s}'", .{result.value});
                std.os.exit(0xff);
            });
            const varname = rest[1 .. end];
            const after = rest[end + 1..];
            const value = try var_map.getSubbed(allocator, filename_for_error, varname);
            const new_value = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{before, value, after});
            result.deinit(allocator);
            result = .{
                .value = new_value,
                .sub_performed = true,
            };
        } else {
            std.log.err("invalid substitution sequence '${c}'", .{rest[0]});
            std.os.exit(0xff);
        }
    }
}
