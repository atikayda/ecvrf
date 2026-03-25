//! RFC 9381 ECVRF-SECP256K1-SHA256-TAI implementation in Zig.
//! Zero external dependencies — uses only the standard library.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Secp256k1 = crypto.ecc.Secp256k1;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const scalar = Secp256k1.scalar;
const Scalar = scalar.Scalar;

const suite_byte: u8 = 0xFE;
pub const proof_len: usize = 81;
pub const beta_len: usize = 32;
const challenge_len: usize = 16;
const scalar_len: usize = 32;
const compressed_len: usize = 33;

pub const ProveError = error{
    InvalidSecretKey,
    EncodeToCurveFailed,
    IdentityElement,
    NonCanonical,
};

fn pointToString(p: Secp256k1) [compressed_len]u8 {
    return p.toCompressedSec1();
}

fn encodeToCurveTai(pk: Secp256k1, alpha: []const u8) error{EncodeToCurveFailed}!Secp256k1 {
    const pk_bytes = pointToString(pk);
    var ctr: u16 = 0;
    while (ctr <= 255) : (ctr += 1) {
        var hasher = Sha256.init(.{});
        hasher.update(&[_]u8{ suite_byte, 0x01 });
        hasher.update(&pk_bytes);
        hasher.update(alpha);
        hasher.update(&[_]u8{@intCast(ctr)});
        hasher.update(&[_]u8{0x00});
        const hash = hasher.finalResult();

        var compressed: [compressed_len]u8 = undefined;
        compressed[0] = 0x02;
        @memcpy(compressed[1..], &hash);

        if (Secp256k1.fromSec1(&compressed)) |point| {
            return point;
        } else |_| {
            continue;
        }
    }
    return error.EncodeToCurveFailed;
}

fn rfc6979Nonce(sk: [scalar_len]u8, h_point: Secp256k1) [scalar_len]u8 {
    const h_bytes = pointToString(h_point);
    var h1: [32]u8 = undefined;
    Sha256.hash(&h_bytes, &h1, .{});

    // bits2octets: reduce h1 modulo group order if needed
    var h1_reduced: [32]u8 = undefined;
    if (Scalar.fromBytes(h1, .big)) |s| {
        h1_reduced = s.toBytes(.big);
    } else |_| {
        var h64: [64]u8 = [_]u8{0} ** 64;
        @memcpy(h64[32..], &h1);
        h1_reduced = scalar.reduce64(h64, .big);
    }

    // RFC 6979 Section 3.2
    var v: [32]u8 = [_]u8{0x01} ** 32;
    var k: [32]u8 = [_]u8{0x00} ** 32;

    // Step D: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    {
        var hmac = HmacSha256.init(&k);
        hmac.update(&v);
        hmac.update(&[_]u8{0x00});
        hmac.update(&sk);
        hmac.update(&h1_reduced);
        hmac.final(&k);
    }

    // Step E: V = HMAC_K(V)
    HmacSha256.create(&v, &v, &k);

    // Step F: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    {
        var hmac = HmacSha256.init(&k);
        hmac.update(&v);
        hmac.update(&[_]u8{0x01});
        hmac.update(&sk);
        hmac.update(&h1_reduced);
        hmac.final(&k);
    }

    // Step G: V = HMAC_K(V)
    HmacSha256.create(&v, &v, &k);

    // Step H: generate candidate nonce
    while (true) {
        HmacSha256.create(&v, &v, &k);

        if (Scalar.fromBytes(v, .big)) |s| {
            if (!s.isZero()) return v;
        } else |_| {}

        // Retry: K = HMAC_K(V || 0x00), V = HMAC_K(V)
        {
            var hmac = HmacSha256.init(&k);
            hmac.update(&v);
            hmac.update(&[_]u8{0x00});
            hmac.final(&k);
        }
        HmacSha256.create(&v, &v, &k);
    }
}

fn challengeGeneration(y: Secp256k1, h: Secp256k1, gamma: Secp256k1, u: Secp256k1, v: Secp256k1) [challenge_len]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{ suite_byte, 0x02 });
    hasher.update(&pointToString(y));
    hasher.update(&pointToString(h));
    hasher.update(&pointToString(gamma));
    hasher.update(&pointToString(u));
    hasher.update(&pointToString(v));
    hasher.update(&[_]u8{0x00});
    const hash = hasher.finalResult();
    return hash[0..challenge_len].*;
}

fn proofToHashFromGamma(gamma: Secp256k1) [beta_len]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{ suite_byte, 0x03 });
    hasher.update(&pointToString(gamma));
    hasher.update(&[_]u8{0x00});
    return hasher.finalResult();
}

/// Generate an 81-byte VRF proof: Gamma(33) || c(16) || s(32).
pub fn prove(sk: *const [scalar_len]u8, alpha: []const u8) ProveError![proof_len]u8 {
    const x = Scalar.fromBytes(sk.*, .big) catch return error.NonCanonical;
    if (x.isZero()) return error.InvalidSecretKey;

    const y = Secp256k1.basePoint.mul(sk.*, .big) catch return error.IdentityElement;
    const h = try encodeToCurveTai(y, alpha);
    const gamma = h.mul(sk.*, .big) catch return error.IdentityElement;
    const k_bytes = rfc6979Nonce(sk.*, h);
    const u = Secp256k1.basePoint.mul(k_bytes, .big) catch return error.IdentityElement;
    const v_point = h.mul(k_bytes, .big) catch return error.IdentityElement;
    const c = challengeGeneration(y, h, gamma, u, v_point);

    // s = (k + c * x) mod n
    var c_32: [scalar_len]u8 = [_]u8{0} ** scalar_len;
    @memcpy(c_32[16..], &c);
    const s = scalar.mulAdd(c_32, sk.*, k_bytes, .big) catch return error.NonCanonical;

    var pi: [proof_len]u8 = undefined;
    const gamma_bytes = pointToString(gamma);
    @memcpy(pi[0..compressed_len], &gamma_bytes);
    @memcpy(pi[compressed_len..][0..challenge_len], &c);
    @memcpy(pi[compressed_len + challenge_len..], &s);
    return pi;
}

/// Verify a VRF proof. Returns beta (32 bytes) if valid, null if invalid.
pub fn verify(pk: []const u8, pi: []const u8, alpha: []const u8) ?[beta_len]u8 {
    if (pi.len != proof_len) return null;

    const gamma = Secp256k1.fromSec1(pi[0..compressed_len]) catch return null;
    gamma.rejectIdentity() catch return null;

    const c_bytes = pi[compressed_len..][0..challenge_len].*;
    const s_bytes = pi[compressed_len + challenge_len..][0..scalar_len].*;

    // s must be < group order
    scalar.rejectNonCanonical(s_bytes, .big) catch return null;

    const y = Secp256k1.fromSec1(pk) catch return null;
    y.rejectIdentity() catch return null;

    const h = encodeToCurveTai(y, alpha) catch return null;

    // U = s*G - c*Y  (computed as s*G + (-c)*Y)
    var c_32: [scalar_len]u8 = [_]u8{0} ** scalar_len;
    @memcpy(c_32[16..], &c_bytes);
    const neg_c = scalar.neg(c_32, .big) catch return null;

    const u = Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, s_bytes, y, neg_c, .big) catch return null;
    const v_point = Secp256k1.mulDoubleBasePublic(h, s_bytes, gamma, neg_c, .big) catch return null;

    const c_prime = challengeGeneration(y, h, gamma, u, v_point);
    if (!mem.eql(u8, &c_bytes, &c_prime)) return null;

    return proofToHashFromGamma(gamma);
}

/// Extract VRF output (beta, 32 bytes) from a proof.
pub fn proofToHash(pi: []const u8) ?[beta_len]u8 {
    if (pi.len != proof_len) return null;
    const gamma = Secp256k1.fromSec1(pi[0..compressed_len]) catch return null;
    return proofToHashFromGamma(gamma);
}

/// Derive compressed public key (33 bytes) from a secret key.
pub fn derivePublicKey(sk: *const [scalar_len]u8) ?[compressed_len]u8 {
    const x = Scalar.fromBytes(sk.*, .big) catch return null;
    if (x.isZero()) return null;
    const y = Secp256k1.basePoint.mul(sk.*, .big) catch return null;
    return pointToString(y);
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;
const json = std.json;

fn parseHexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => unreachable,
    };
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const len = hex.len / 2;
    if (len == 0) return allocator.alloc(u8, 0);
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        buf[i] = (parseHexDigit(hex[2 * i]) << 4) | parseHexDigit(hex[2 * i + 1]);
    }
    return buf;
}

fn hexToFixed(comptime N: usize, hex: []const u8) [N]u8 {
    var buf: [N]u8 = undefined;
    for (0..N) |i| {
        buf[i] = (parseHexDigit(hex[2 * i]) << 4) | parseHexDigit(hex[2 * i + 1]);
    }
    return buf;
}

fn bytesToHex(comptime N: usize, bytes: [N]u8) [N * 2]u8 {
    const charset = "0123456789abcdef";
    var hex: [N * 2]u8 = undefined;
    for (0..N) |i| {
        hex[2 * i] = charset[bytes[i] >> 4];
        hex[2 * i + 1] = charset[bytes[i] & 0x0f];
    }
    return hex;
}

fn sliceToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const charset = "0123456789abcdef";
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (0..bytes.len) |i| {
        hex[2 * i] = charset[bytes[i] >> 4];
        hex[2 * i + 1] = charset[bytes[i] & 0x0f];
    }
    return hex;
}

const TestVector = struct {
    label: []const u8,
    sk: []const u8,
    pk: []const u8,
    alpha: []const u8,
    pi: []const u8,
    beta: []const u8,
};

const NegativeVector = struct {
    description: []const u8,
    pk: []const u8,
    alpha: []const u8,
    pi: []const u8,
    expected_verify: bool,
};

const VectorFile = struct {
    suite: []const u8,
    spec: []const u8,
    vectors: []const TestVector,
    negative_vectors: []const NegativeVector,
};

const Vectors = struct {
    parsed: json.Parsed(VectorFile),
    json_buf: []u8,
    allocator: std.mem.Allocator,

    fn load(allocator: std.mem.Allocator) !Vectors {
        const file = try std.fs.cwd().openFile("../vectors/vectors.json", .{});
        defer file.close();
        const json_buf = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
        const parsed = try json.parseFromSlice(VectorFile, allocator, json_buf, .{
            .ignore_unknown_fields = true,
        });
        return .{ .parsed = parsed, .json_buf = json_buf, .allocator = allocator };
    }

    fn deinit(self: *Vectors) void {
        self.parsed.deinit();
        self.allocator.free(self.json_buf);
    }
};

test "prove" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.vectors) |vec| {
        const sk = hexToFixed(32, vec.sk);
        const alpha = try hexDecode(allocator, vec.alpha);
        defer allocator.free(alpha);

        const pi = prove(&sk, alpha) catch |err| {
            std.debug.print("prove failed for '{s}': {}\n", .{ vec.label, err });
            return err;
        };

        const got = bytesToHex(proof_len, pi);
        if (!mem.eql(u8, &got, vec.pi)) {
            std.debug.print("pi mismatch for '{s}'\n  got:  {s}\n  want: {s}\n", .{ vec.label, &got, vec.pi });
            return error.TestExpectedEqual;
        }
    }
}

test "verify" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.vectors) |vec| {
        const pk = try hexDecode(allocator, vec.pk);
        defer allocator.free(pk);
        const alpha = try hexDecode(allocator, vec.alpha);
        defer allocator.free(alpha);
        const pi = try hexDecode(allocator, vec.pi);
        defer allocator.free(pi);

        const beta = verify(pk, pi, alpha) orelse {
            std.debug.print("verify returned invalid for '{s}'\n", .{vec.label});
            return error.TestExpectedEqual;
        };

        const got = bytesToHex(beta_len, beta);
        if (!mem.eql(u8, &got, vec.beta)) {
            std.debug.print("beta mismatch for '{s}'\n  got:  {s}\n  want: {s}\n", .{ vec.label, &got, vec.beta });
            return error.TestExpectedEqual;
        }
    }
}

test "proof_to_hash" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.vectors) |vec| {
        const pi = try hexDecode(allocator, vec.pi);
        defer allocator.free(pi);

        const beta = proofToHash(pi) orelse {
            std.debug.print("proofToHash returned null for '{s}'\n", .{vec.label});
            return error.TestExpectedEqual;
        };

        const got = bytesToHex(beta_len, beta);
        if (!mem.eql(u8, &got, vec.beta)) {
            std.debug.print("beta mismatch for '{s}'\n  got:  {s}\n  want: {s}\n", .{ vec.label, &got, vec.beta });
            return error.TestExpectedEqual;
        }
    }
}

test "negative_verify" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.negative_vectors) |vec| {
        const pk = try hexDecode(allocator, vec.pk);
        defer allocator.free(pk);
        const alpha = try hexDecode(allocator, vec.alpha);
        defer allocator.free(alpha);
        const pi = try hexDecode(allocator, vec.pi);
        defer allocator.free(pi);

        const result = verify(pk, pi, alpha);
        const valid = result != null;
        if (valid != vec.expected_verify) {
            std.debug.print("negative verify: expected {}, got {} for '{s}'\n", .{ vec.expected_verify, valid, vec.description });
            return error.TestExpectedEqual;
        }
    }
}

test "determinism" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    if (vecs.parsed.value.vectors.len == 0) return;
    const vec = vecs.parsed.value.vectors[0];
    const sk = hexToFixed(32, vec.sk);
    const alpha = try hexDecode(allocator, vec.alpha);
    defer allocator.free(alpha);

    const pi1 = try prove(&sk, alpha);
    const pi2 = try prove(&sk, alpha);

    try testing.expectEqualSlices(u8, &pi1, &pi2);
}

test "round_trip" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.vectors) |vec| {
        const sk = hexToFixed(32, vec.sk);
        const alpha = try hexDecode(allocator, vec.alpha);
        defer allocator.free(alpha);

        const pi = try prove(&sk, alpha);

        const pk = derivePublicKey(&sk) orelse return error.TestExpectedEqual;

        const beta = verify(&pk, &pi, alpha) orelse {
            std.debug.print("round-trip verify failed for '{s}'\n", .{vec.label});
            return error.TestExpectedEqual;
        };

        const beta_from_hash = proofToHash(&pi) orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, &beta, &beta_from_hash);
    }
}

test "derive_public_key" {
    const allocator = testing.allocator;
    var vecs = try Vectors.load(allocator);
    defer vecs.deinit();

    for (vecs.parsed.value.vectors) |vec| {
        const sk = hexToFixed(32, vec.sk);
        const pk = derivePublicKey(&sk) orelse {
            std.debug.print("derivePublicKey failed for '{s}'\n", .{vec.label});
            return error.TestExpectedEqual;
        };

        const got = bytesToHex(compressed_len, pk);
        if (!mem.eql(u8, &got, vec.pk)) {
            std.debug.print("pk mismatch for '{s}'\n  got:  {s}\n  want: {s}\n", .{ vec.label, &got, vec.pk });
            return error.TestExpectedEqual;
        }
    }
}

test "prove_rejects_invalid_sk" {
    const zero_sk = [_]u8{0} ** 32;
    try testing.expectError(error.InvalidSecretKey, prove(&zero_sk, "test"));

    // sk = group order
    const n = hexToFixed(32, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    try testing.expectError(error.NonCanonical, prove(&n, "test"));
}
