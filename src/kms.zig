//! Minimal AWS KMS client for Ethereum signing with `ECC_SECG_P256K1` keys.
//!
//! Provides just the two KMS operations an Ethereum signer needs - `Sign` and
//! `GetPublicKey` - plus the SigV4 request signing and credential resolution
//! they require. The private key never leaves KMS: this client only asks KMS to
//! sign a 32-byte digest (returning a DER ECDSA signature) and to return the
//! public key (for address derivation).
//!
//! Credentials are resolved per call from the standard sources: static
//! environment variables, then the ECS/Fargate container-credentials endpoint.
//! SigV4 uses HMAC-SHA256 (baseline-CPU safe - no wide-integer math), so this
//! builds and runs on Fargate with `-Dcpu=baseline`.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const KmsError = error{
    CredentialsUnavailable,
    RequestFailed,
    Unauthorized,
    ResponseInvalid,
} || std.mem.Allocator.Error;

/// Resolved AWS credentials. All fields are allocator-owned.
pub const Credentials = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8,

    pub fn deinit(self: *Credentials, allocator: std.mem.Allocator) void {
        allocator.free(self.access_key_id);
        allocator.free(self.secret_access_key);
        if (self.session_token) |t| allocator.free(t);
        self.* = undefined;
    }
};

/// AWS KMS client. Holds an HTTP client bound to the given `io`; the caller owns
/// it and must keep it alive for the client's lifetime.
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// AWS region, e.g. "us-west-2". Borrowed; caller keeps it alive.
    region: []const u8,
    http: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, region: []const u8) Client {
        return .{
            .allocator = allocator,
            .io = io,
            .region = region,
            .http = .{ .allocator = allocator, .io = io },
        };
    }

    pub fn deinit(self: *Client) void {
        self.http.deinit();
    }

    /// KMS `Sign` over a 32-byte digest with `ECDSA_SHA_256`. Returns the raw
    /// `(r, s)` as 64 big-endian bytes (r||s), decoded from KMS's DER signature.
    /// `s` is NOT normalized here - the caller applies EIP-2 low-s.
    pub fn sign(self: *Client, key_id: []const u8, digest: [32]u8) KmsError![64]u8 {
        var msg_b64_buf: [64]u8 = undefined;
        const msg_b64 = std.base64.standard.Encoder.encode(&msg_b64_buf, &digest);

        const body = try std.fmt.allocPrint(
            self.allocator,
            "{{\"KeyId\":\"{s}\",\"Message\":\"{s}\",\"MessageType\":\"DIGEST\",\"SigningAlgorithm\":\"ECDSA_SHA_256\"}}",
            .{ key_id, msg_b64 },
        );
        defer self.allocator.free(body);

        const resp = try self.call("TrentService.Sign", body);
        defer self.allocator.free(resp);

        const der = try decodeBase64Field(self.allocator, resp, "Signature");
        defer self.allocator.free(der);

        return decodeDerSignature(der);
    }

    /// KMS `GetPublicKey`. Returns the 65-byte uncompressed secp256k1 public key
    /// (`0x04 || X || Y`) extracted from the DER SubjectPublicKeyInfo.
    pub fn getPublicKey(self: *Client, key_id: []const u8) KmsError![65]u8 {
        const body = try std.fmt.allocPrint(self.allocator, "{{\"KeyId\":\"{s}\"}}", .{key_id});
        defer self.allocator.free(body);

        const resp = try self.call("TrentService.GetPublicKey", body);
        defer self.allocator.free(resp);

        const spki = try decodeBase64Field(self.allocator, resp, "PublicKey");
        defer self.allocator.free(spki);

        return extractUncompressedPubkey(spki);
    }

    /// Perform a SigV4-signed KMS POST and return the response body (owned).
    fn call(self: *Client, target: []const u8, body: []const u8) KmsError![]u8 {
        var creds = try resolveCredentials(self.allocator, self.io);
        defer creds.deinit(self.allocator);

        const host = try std.fmt.allocPrint(self.allocator, "kms.{s}.amazonaws.com", .{self.region});
        defer self.allocator.free(host);
        const url = try std.fmt.allocPrint(self.allocator, "https://{s}/", .{host});
        defer self.allocator.free(url);

        const ts = try nowTimestamps(self.io);
        const authorization = try signRequestV4(self.allocator, .{
            .region = self.region,
            .host = host,
            .target = target,
            .body = body,
            .creds = creds,
            .amz_date = ts.amz_date(),
            .date_stamp = ts.date_stamp(),
        });
        defer self.allocator.free(authorization);

        var header_buf: [5]std.http.Header = undefined;
        var n: usize = 0;
        header_buf[n] = .{ .name = "Content-Type", .value = "application/x-amz-json-1.1" };
        n += 1;
        header_buf[n] = .{ .name = "X-Amz-Target", .value = target };
        n += 1;
        header_buf[n] = .{ .name = "X-Amz-Date", .value = ts.amz_date() };
        n += 1;
        header_buf[n] = .{ .name = "Authorization", .value = authorization };
        n += 1;
        if (creds.session_token) |tok| {
            header_buf[n] = .{ .name = "X-Amz-Security-Token", .value = tok };
            n += 1;
        }

        // Signing calls can be minutes apart, and KMS closes idle keep-alive
        // connections well before that, so the pooled connection is routinely
        // dead by the next call and the first write fails. The failed fetch
        // discards that connection; one retry dials fresh.
        var attempt: u2 = 0;
        while (true) : (attempt += 1) {
            var response_body: std.Io.Writer.Allocating = .init(self.allocator);

            const result = self.http.fetch(.{
                .location = .{ .url = url },
                .method = .POST,
                .payload = body,
                .extra_headers = header_buf[0..n],
                .response_writer = &response_body.writer,
            }) catch {
                response_body.deinit();
                if (attempt == 0) continue;
                return KmsError.RequestFailed;
            };

            if (result.status == .ok) {
                errdefer response_body.deinit();
                return response_body.toOwnedSlice();
            }

            response_body.deinit();
            return switch (result.status) {
                .forbidden, .unauthorized => KmsError.Unauthorized,
                else => KmsError.RequestFailed,
            };
        }
    }
};

// ============================================================================
// Credentials
// ============================================================================

/// Resolve AWS credentials: static env vars first, then the ECS/Fargate
/// container-credentials endpoint.
pub fn resolveCredentials(allocator: std.mem.Allocator, io: std.Io) KmsError!Credentials {
    if (envOwned(allocator, "AWS_ACCESS_KEY_ID")) |access_key| {
        if (envOwned(allocator, "AWS_SECRET_ACCESS_KEY")) |secret_key| {
            return .{
                .access_key_id = access_key,
                .secret_access_key = secret_key,
                .session_token = envOwned(allocator, "AWS_SESSION_TOKEN"),
            };
        } else {
            allocator.free(access_key);
        }
    }

    // ECS/Fargate container credentials provider.
    const url = containerCredentialsUrl(allocator) orelse return KmsError.CredentialsUnavailable;
    defer allocator.free(url);

    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();

    var response_body: std.Io.Writer.Allocating = .init(allocator);
    defer response_body.deinit();

    const result = http.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_writer = &response_body.writer,
    }) catch return KmsError.CredentialsUnavailable;
    if (result.status != .ok) return KmsError.CredentialsUnavailable;

    const Parsed = struct {
        AccessKeyId: []const u8,
        SecretAccessKey: []const u8,
        Token: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Parsed, allocator, response_body.written(), .{
        .ignore_unknown_fields = true,
    }) catch return KmsError.CredentialsUnavailable;
    defer parsed.deinit();

    // Dupe field-by-field with errdefer so an allocation failure mid-way frees
    // the fields already duplicated instead of leaking them.
    const access_key_id = try allocator.dupe(u8, parsed.value.AccessKeyId);
    errdefer allocator.free(access_key_id);
    const secret_access_key = try allocator.dupe(u8, parsed.value.SecretAccessKey);
    errdefer allocator.free(secret_access_key);
    const session_token = if (parsed.value.Token) |t| try allocator.dupe(u8, t) else null;

    return .{
        .access_key_id = access_key_id,
        .secret_access_key = secret_access_key,
        .session_token = session_token,
    };
}

/// Read an environment variable via libc `getenv`, returning an allocator-owned
/// copy or null. Zig 0.16 moved ambient env access behind the `Io` model and
/// removed `std.process.getEnvVarOwned`; eth.zig links libc (for its crypto C),
/// so `std.c.getenv` is the portable POSIX path (the same one `std.start` and the
/// bots use).
fn envOwned(allocator: std.mem.Allocator, name: [*:0]const u8) ?[]const u8 {
    const raw = std.c.getenv(name) orelse return null;
    return allocator.dupe(u8, std.mem.span(raw)) catch null;
}

/// Build the container-credentials URL from the standard env vars, or null if
/// neither is set. `AWS_CONTAINER_CREDENTIALS_FULL_URI` wins; otherwise
/// `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` is appended to the ECS metadata IP.
fn containerCredentialsUrl(allocator: std.mem.Allocator) ?[]const u8 {
    if (std.c.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")) |full| {
        return allocator.dupe(u8, std.mem.span(full)) catch null;
    }
    if (std.c.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) |rel| {
        return std.fmt.allocPrint(allocator, "http://169.254.170.2{s}", .{std.mem.span(rel)}) catch null;
    }
    return null;
}

// ============================================================================
// SigV4
// ============================================================================

const SignParams = struct {
    region: []const u8,
    host: []const u8,
    target: []const u8,
    body: []const u8,
    creds: Credentials,
    amz_date: []const u8, // YYYYMMDDTHHMMSSZ
    date_stamp: []const u8, // YYYYMMDD
};

/// Compute the SigV4 `Authorization` header value for a KMS POST. Returns an
/// allocator-owned string.
pub fn signRequestV4(allocator: std.mem.Allocator, p: SignParams) KmsError![]u8 {
    const service = "kms";

    // Canonical + signed headers. Names must be lowercase and sorted; the set
    // here is always: content-type, host, x-amz-date, [x-amz-security-token], x-amz-target.
    const payload_hash = hexSha256(p.body);

    const canonical_headers = if (p.creds.session_token) |tok|
        try std.fmt.allocPrint(allocator, "content-type:application/x-amz-json-1.1\nhost:{s}\nx-amz-date:{s}\nx-amz-security-token:{s}\nx-amz-target:{s}\n", .{ p.host, p.amz_date, tok, p.target })
    else
        try std.fmt.allocPrint(allocator, "content-type:application/x-amz-json-1.1\nhost:{s}\nx-amz-date:{s}\nx-amz-target:{s}\n", .{ p.host, p.amz_date, p.target });
    defer allocator.free(canonical_headers);

    const signed_headers: []const u8 = if (p.creds.session_token != null)
        "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
    else
        "content-type;host;x-amz-date;x-amz-target";

    const canonical_request = try std.fmt.allocPrint(
        allocator,
        "POST\n/\n\n{s}\n{s}\n{s}",
        .{ canonical_headers, signed_headers, &payload_hash },
    );
    defer allocator.free(canonical_request);

    const credential_scope = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}/aws4_request",
        .{ p.date_stamp, p.region, service },
    );
    defer allocator.free(credential_scope);

    const cr_hash = hexSha256(canonical_request);
    const string_to_sign = try std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256\n{s}\n{s}\n{s}",
        .{ p.amz_date, credential_scope, &cr_hash },
    );
    defer allocator.free(string_to_sign);

    const signing_key = deriveSigningKey(p.creds.secret_access_key, p.date_stamp, p.region, service);
    var sig_raw: [32]u8 = undefined;
    HmacSha256.create(&sig_raw, string_to_sign, &signing_key);
    const signature = std.fmt.bytesToHex(sig_raw, .lower);

    return std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ p.creds.access_key_id, credential_scope, signed_headers, &signature },
    );
}

/// SigV4 signing key: HMAC chain over "AWS4"+secret, date, region, service.
fn deriveSigningKey(secret: []const u8, date_stamp: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var k_secret_buf: [4 + 128]u8 = undefined;
    const prefix = "AWS4";
    @memcpy(k_secret_buf[0..4], prefix);
    const secret_len = @min(secret.len, k_secret_buf.len - 4);
    @memcpy(k_secret_buf[4 .. 4 + secret_len], secret[0..secret_len]);
    const k_secret = k_secret_buf[0 .. 4 + secret_len];

    var k_date: [32]u8 = undefined;
    HmacSha256.create(&k_date, date_stamp, k_secret);
    var k_region: [32]u8 = undefined;
    HmacSha256.create(&k_region, region, &k_date);
    var k_service: [32]u8 = undefined;
    HmacSha256.create(&k_service, service, &k_region);
    var k_signing: [32]u8 = undefined;
    HmacSha256.create(&k_signing, "aws4_request", &k_service);
    return k_signing;
}

fn hexSha256(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

// ============================================================================
// Timestamps
// ============================================================================

const Timestamps = struct {
    buf_amz: [16]u8,
    buf_date: [8]u8,

    fn amz_date(self: *const Timestamps) []const u8 {
        return &self.buf_amz;
    }
    fn date_stamp(self: *const Timestamps) []const u8 {
        return &self.buf_date;
    }
};

/// Current UTC time formatted for SigV4: `YYYYMMDDTHHMMSSZ` and `YYYYMMDD`.
/// Zig 0.16 reads wall-clock time through `Io` (`std.time.timestamp` was removed).
fn nowTimestamps(io: std.Io) KmsError!Timestamps {
    const now = std.Io.Clock.now(.real, io).toSeconds();
    if (now < 0) return KmsError.RequestFailed;
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(now) };
    const day = epoch_secs.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const ds = epoch_secs.getDaySeconds();

    const year: u16 = year_day.year;
    const month: u8 = month_day.month.numeric();
    const dom: u8 = month_day.day_index + 1;
    const hour: u8 = ds.getHoursIntoDay();
    const minute: u8 = ds.getMinutesIntoHour();
    const second: u8 = ds.getSecondsIntoMinute();

    var out: Timestamps = .{ .buf_amz = undefined, .buf_date = undefined };
    _ = std.fmt.bufPrint(&out.buf_amz, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{ year, month, dom, hour, minute, second }) catch return KmsError.RequestFailed;
    _ = std.fmt.bufPrint(&out.buf_date, "{d:0>4}{d:0>2}{d:0>2}", .{ year, month, dom }) catch return KmsError.RequestFailed;
    return out;
}

// ============================================================================
// JSON + base64 + DER decoding
// ============================================================================

/// Parse `resp` as JSON and base64-decode the string field `field`. Owned result.
fn decodeBase64Field(allocator: std.mem.Allocator, resp: []const u8, comptime field: []const u8) KmsError![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch return KmsError.ResponseInvalid;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return KmsError.ResponseInvalid,
    };
    const val = obj.get(field) orelse return KmsError.ResponseInvalid;
    const b64 = switch (val) {
        .string => |s| s,
        else => return KmsError.ResponseInvalid,
    };

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return KmsError.ResponseInvalid;
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    std.base64.standard.Decoder.decode(out, b64) catch return KmsError.ResponseInvalid;
    return out;
}

/// Decode a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }`
/// into 64 big-endian bytes `r||s` (each 32 bytes, left-padded). Strict: the
/// SEQUENCE length must span exactly the rest of the input, and both INTEGERs
/// must consume it fully - trailing or embedded extra bytes are rejected.
pub fn decodeDerSignature(der: []const u8) KmsError![64]u8 {
    var pos: usize = 0;
    if (der.len < 8 or der[pos] != 0x30) return KmsError.ResponseInvalid;
    pos += 1;
    // SEQUENCE length (short form only; a secp256k1 ECDSA sig is < 128 bytes)
    // and it must match the remaining input exactly.
    const seq_len = der[pos];
    if (seq_len & 0x80 != 0) return KmsError.ResponseInvalid;
    pos += 1;
    if (der.len != pos + seq_len) return KmsError.ResponseInvalid;

    var out: [64]u8 = @splat(0);
    pos = try readDerInteger(der, pos, out[0..32]);
    pos = try readDerInteger(der, pos, out[32..64]);
    if (pos != der.len) return KmsError.ResponseInvalid;
    return out;
}

/// Read a DER INTEGER at `der[pos]` into the 32-byte big-endian `dst`
/// (right-aligned). Returns the position just past the integer.
fn readDerInteger(der: []const u8, pos_in: usize, dst: *[32]u8) KmsError!usize {
    var pos = pos_in;
    if (pos + 2 > der.len or der[pos] != 0x02) return KmsError.ResponseInvalid;
    pos += 1;
    const len = der[pos];
    pos += 1;
    if (len == 0 or len & 0x80 != 0 or pos + len > der.len) return KmsError.ResponseInvalid;

    var start = pos;
    var remaining = len;
    // Strip a single leading 0x00 (present when the high bit would set the sign).
    while (remaining > 1 and der[start] == 0x00) {
        start += 1;
        remaining -= 1;
    }
    if (remaining > 32) return KmsError.ResponseInvalid;
    @memcpy(dst[32 - remaining .. 32], der[start .. start + remaining]);
    return pos + len;
}

/// Extract the 65-byte uncompressed public key (`0x04 || X || Y`) from a DER
/// SubjectPublicKeyInfo. The key is the final 65 bytes of the SPKI.
pub fn extractUncompressedPubkey(spki: []const u8) KmsError![65]u8 {
    if (spki.len < 65) return KmsError.ResponseInvalid;
    const start = spki.len - 65;
    if (spki[start] != 0x04) return KmsError.ResponseInvalid;
    var out: [65]u8 = undefined;
    @memcpy(&out, spki[start..]);
    return out;
}

// ============================================================================
// Tests
// ============================================================================

test "SigV4 signing key + signature match the AWS documented vector" {
    // From "Examples of the complete Version 4 signing process" (AWS docs):
    // GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08
    const secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const date_stamp = "20150830";
    const region = "us-east-1";
    const service = "iam";
    const string_to_sign =
        "AWS4-HMAC-SHA256\n" ++
        "20150830T123600Z\n" ++
        "20150830/us-east-1/iam/aws4_request\n" ++
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

    const signing_key = deriveSigningKey(secret, date_stamp, region, service);
    var sig_raw: [32]u8 = undefined;
    HmacSha256.create(&sig_raw, string_to_sign, &signing_key);
    const signature = std.fmt.bytesToHex(sig_raw, .lower);

    try std.testing.expectEqualStrings(
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        &signature,
    );
}

test "hexSha256 of empty string" {
    const h = hexSha256("");
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        &h,
    );
}

test "decodeDerSignature round-trips r and s (no padding)" {
    // SEQUENCE(len=6) { INTEGER(1) 0x01, INTEGER(1) 0x02 }
    const der = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    const rs = try decodeDerSignature(&der);
    try std.testing.expectEqual(@as(u8, 0x01), rs[31]);
    try std.testing.expectEqual(@as(u8, 0x02), rs[63]);
    // Everything else is zero-padded.
    for (rs[0..31]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    for (rs[32..63]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "decodeDerSignature strips leading sign byte" {
    // r = 0x00FF... (leading zero to keep it positive) should decode to 0xFF in
    // the last byte, not shift the value.
    const der = [_]u8{ 0x30, 0x08, 0x02, 0x02, 0x00, 0xff, 0x02, 0x02, 0x00, 0x80 };
    const rs = try decodeDerSignature(&der);
    try std.testing.expectEqual(@as(u8, 0xff), rs[31]);
    try std.testing.expectEqual(@as(u8, 0x80), rs[63]);
}

test "decodeDerSignature rejects trailing bytes after the sequence" {
    // Valid minimal sig followed by one garbage byte.
    const der = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xff };
    try std.testing.expectError(KmsError.ResponseInvalid, decodeDerSignature(&der));
}

test "decodeDerSignature rejects sequence length mismatch" {
    // SEQUENCE claims 7 bytes of content but only 6 follow.
    const der = [_]u8{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
    try std.testing.expectError(KmsError.ResponseInvalid, decodeDerSignature(&der));
}

test "decodeDerSignature rejects zero-length integers" {
    // r is INTEGER of length 0 (padded with an extra s byte to pass the min-len gate).
    const der = [_]u8{ 0x30, 0x07, 0x02, 0x00, 0x02, 0x03, 0x01, 0x02, 0x03 };
    try std.testing.expectError(KmsError.ResponseInvalid, decodeDerSignature(&der));
}

test "extractUncompressedPubkey pulls the trailing 65 bytes" {
    var spki: [88]u8 = @splat(0xaa);
    spki[spki.len - 65] = 0x04;
    // Fill X||Y with a recognizable pattern.
    for (spki[spki.len - 64 ..], 0..) |*b, i| b.* = @intCast(i & 0xff);
    const pk = try extractUncompressedPubkey(&spki);
    try std.testing.expectEqual(@as(u8, 0x04), pk[0]);
    try std.testing.expectEqual(@as(u8, 0), pk[1]);
    try std.testing.expectEqual(@as(u8, 63), pk[64]);
}
