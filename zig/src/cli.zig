const std = @import("std");
const ecvrf = @import("ecvrf.zig");

fn parseHexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const len = hex.len / 2;
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        buf[i] = (parseHexDigit(hex[2 * i]) << 4) | parseHexDigit(hex[2 * i + 1]);
    }
    return buf;
}

fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const charset = "0123456789abcdef";
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (0..bytes.len) |i| {
        hex[2 * i] = charset[bytes[i] >> 4];
        hex[2 * i + 1] = charset[bytes[i] & 0x0f];
    }
    return hex;
}

fn readAlpha(allocator: std.mem.Allocator, args: []const []const u8, idx: usize) ![]const u8 {
    if (idx < args.len and std.mem.eql(u8, args[idx], "--alpha-file") and idx + 1 < args.len) {
        const data = try std.fs.cwd().readFileAlloc(allocator, args[idx + 1], 10 * 1024 * 1024);
        return std.mem.trim(u8, data, &[_]u8{ '\n', '\r', ' ' });
    }
    if (idx < args.len)
        return args[idx];
    return error.MissingArgument;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        const se: std.fs.File = .stderr();
        se.writeAll("usage: ecvrf-zig prove|verify ...\n") catch {};
        std.process.exit(1);
    }

    const so: std.fs.File = .stdout();
    const se: std.fs.File = .stderr();

    if (std.mem.eql(u8, args[1], "prove")) {
        if (args.len < 4) {
            se.writeAll("usage: ecvrf-zig prove <sk_hex> <alpha_hex|--alpha-file path>\n") catch {};
            std.process.exit(1);
        }
        const sk_hex = args[2];
        if (sk_hex.len != 64) {
            se.writeAll("invalid sk hex length\n") catch {};
            std.process.exit(1);
        }
        var sk: [32]u8 = undefined;
        for (0..32) |i| {
            sk[i] = (parseHexDigit(sk_hex[2 * i]) << 4) | parseHexDigit(sk_hex[2 * i + 1]);
        }
        const alpha_hex = try readAlpha(allocator, args, 3);
        const alpha = try hexDecode(allocator, alpha_hex);
        defer allocator.free(alpha);

        const pi = ecvrf.prove(&sk, alpha) catch {
            se.writeAll("prove failed\n") catch {};
            std.process.exit(1);
        };
        const beta = ecvrf.proofToHash(&pi) orelse {
            se.writeAll("proof_to_hash failed\n") catch {};
            std.process.exit(1);
        };
        const pi_hex = try hexEncode(allocator, &pi);
        defer allocator.free(pi_hex);
        const beta_hex = try hexEncode(allocator, &beta);
        defer allocator.free(beta_hex);

        var buf: [512]u8 = undefined;
        const out = std.fmt.bufPrint(&buf, "{{\"pi\":\"{s}\",\"beta\":\"{s}\"}}\n", .{ pi_hex, beta_hex }) catch unreachable;
        so.writeAll(out) catch {};
    } else if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len < 5) {
            se.writeAll("usage: ecvrf-zig verify <pk_hex> <pi_hex> <alpha_hex|--alpha-file path>\n") catch {};
            std.process.exit(1);
        }
        const pk = try hexDecode(allocator, args[2]);
        defer allocator.free(pk);
        const pi = try hexDecode(allocator, args[3]);
        defer allocator.free(pi);
        const alpha_hex = try readAlpha(allocator, args, 4);
        const alpha = try hexDecode(allocator, alpha_hex);
        defer allocator.free(alpha);

        if (ecvrf.verify(pk, pi, alpha)) |beta| {
            const beta_hex = try hexEncode(allocator, &beta);
            defer allocator.free(beta_hex);
            var buf: [256]u8 = undefined;
            const out = std.fmt.bufPrint(&buf, "{{\"valid\":true,\"beta\":\"{s}\"}}\n", .{beta_hex}) catch unreachable;
            so.writeAll(out) catch {};
        } else {
            so.writeAll("{\"valid\":false,\"beta\":null}\n") catch {};
        }
    } else {
        se.writeAll("unknown command\n") catch {};
        std.process.exit(1);
    }
}
