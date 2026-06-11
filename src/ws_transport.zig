const std = @import("std");
const json_rpc = @import("json_rpc.zig");
const runtime = @import("runtime.zig");

/// Minimal WebSocket transport for JSON-RPC over ws:// and wss:// URLs.
///
/// Implements RFC 6455 framing on top of std.Io.net.Stream with optional TLS.
/// This is a synchronous (blocking) implementation suitable for use with
/// Ethereum JSON-RPC subscriptions and requests.

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

pub const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    is_tls: bool,
};

pub const UrlError = error{
    InvalidScheme,
    MissingHost,
};

/// Parse a ws:// or wss:// URL into components.
pub fn parseUrl(url: []const u8) UrlError!ParsedUrl {
    var rest: []const u8 = undefined;
    var is_tls: bool = false;

    if (std.mem.startsWith(u8, url, "wss://")) {
        rest = url[6..];
        is_tls = true;
    } else if (std.mem.startsWith(u8, url, "ws://")) {
        rest = url[5..];
        is_tls = false;
    } else {
        return error.InvalidScheme;
    }

    if (rest.len == 0) return error.MissingHost;

    // Split host+port from path.
    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";

    // Split host from port.
    var host: []const u8 = undefined;
    var port: u16 = if (is_tls) 443 else 80;

    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        host = host_port[0..colon];
        const port_str = host_port[colon + 1 ..];
        port = std.fmt.parseInt(u16, port_str, 10) catch {
            return error.MissingHost;
        };
    } else {
        host = host_port;
    }

    if (host.len == 0) return error.MissingHost;

    return .{
        .host = host,
        .port = port,
        .path = path,
        .is_tls = is_tls,
    };
}

// ---------------------------------------------------------------------------
// WebSocket frame constants
// ---------------------------------------------------------------------------

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,
};

// ---------------------------------------------------------------------------
// Frame encoding (client -> server, always masked)
// ---------------------------------------------------------------------------

/// Build a masked WebSocket frame for the given opcode and payload.
/// Caller owns the returned memory.
pub fn encodeFrame(allocator: std.mem.Allocator, opcode: Opcode, payload: []const u8, mask_key: [4]u8) ![]u8 {
    // Calculate frame size: 2 header bytes + extended length + 4 mask bytes + payload
    var header_len: usize = 2 + 4; // base header + mask key
    if (payload.len >= 126 and payload.len <= 0xFFFF) {
        header_len += 2; // 16-bit extended length
    } else if (payload.len > 0xFFFF) {
        header_len += 8; // 64-bit extended length
    }

    const frame = try allocator.alloc(u8, header_len + payload.len);
    errdefer allocator.free(frame);

    // Byte 0: FIN + opcode
    frame[0] = 0x80 | @as(u8, @intFromEnum(opcode));

    // Byte 1: MASK bit + payload length
    var offset: usize = 2;
    if (payload.len < 126) {
        frame[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= 0xFFFF) {
        frame[1] = 0x80 | 126;
        frame[2] = @intCast((payload.len >> 8) & 0xFF);
        frame[3] = @intCast(payload.len & 0xFF);
        offset = 4;
    } else {
        frame[1] = 0x80 | 127;
        const len64: u64 = @intCast(payload.len);
        inline for (0..8) |i| {
            frame[2 + i] = @intCast((len64 >> @intCast(56 - i * 8)) & 0xFF);
        }
        offset = 10;
    }

    // Masking key
    frame[offset] = mask_key[0];
    frame[offset + 1] = mask_key[1];
    frame[offset + 2] = mask_key[2];
    frame[offset + 3] = mask_key[3];
    offset += 4;

    // Masked payload
    for (payload, 0..) |byte, i| {
        frame[offset + i] = byte ^ mask_key[i % 4];
    }

    return frame;
}

/// Decode a WebSocket frame header, returning the opcode, fin bit, payload
/// length, and whether it is masked. Does NOT consume the payload.
pub const FrameHeader = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: [4]u8,
    header_size: usize,
};

/// Parse a WebSocket frame header from raw bytes.
/// Returns null if there are not enough bytes yet.
pub fn decodeFrameHeader(data: []const u8) ?FrameHeader {
    if (data.len < 2) return null;

    const fin = (data[0] & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @intCast(data[0] & 0x0F)));
    const masked = (data[1] & 0x80) != 0;
    var payload_len: u64 = data[1] & 0x7F;
    var offset: usize = 2;

    if (payload_len == 126) {
        if (data.len < 4) return null;
        payload_len = (@as(u64, data[2]) << 8) | @as(u64, data[3]);
        offset = 4;
    } else if (payload_len == 127) {
        if (data.len < 10) return null;
        payload_len = 0;
        inline for (0..8) |i| {
            payload_len |= @as(u64, data[2 + i]) << @intCast(56 - i * 8);
        }
        offset = 10;
    }

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (data.len < offset + 4) return null;
        mask_key[0] = data[offset];
        mask_key[1] = data[offset + 1];
        mask_key[2] = data[offset + 2];
        mask_key[3] = data[offset + 3];
        offset += 4;
    }

    return .{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload_len = payload_len,
        .mask_key = mask_key,
        .header_size = offset,
    };
}

/// Unmask a payload in place given a 4-byte mask key.
pub fn unmaskPayload(payload: []u8, mask_key: [4]u8) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= mask_key[i % 4];
    }
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

/// Build the HTTP upgrade request for WebSocket handshake.
/// Returns the request bytes. Caller owns the returned memory.
pub fn buildHandshakeRequest(allocator: std.mem.Allocator, host: []const u8, port: u16, path: []const u8, ws_key: []const u8) ![]u8 {
    // Determine if we need to include port in the Host header.
    // Only include non-standard ports.
    var host_header_buf: [256]u8 = undefined;
    const host_header = blk: {
        if (port == 80 or port == 443) {
            break :blk std.fmt.bufPrint(&host_header_buf, "{s}", .{host}) catch return error.OutOfMemory;
        } else {
            break :blk std.fmt.bufPrint(&host_header_buf, "{s}:{d}", .{ host, port }) catch return error.OutOfMemory;
        }
    };

    const request_fmt =
        "GET {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    return std.fmt.allocPrint(allocator, request_fmt, .{ path, host_header, ws_key }) catch return error.OutOfMemory;
}

/// Generate a base64-encoded Sec-WebSocket-Key from 16 random bytes.
pub fn generateWebSocketKey(random_bytes: [16]u8) [24]u8 {
    var result: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&result, &random_bytes);
    return result;
}

/// Compute the expected Sec-WebSocket-Accept value for a given key.
/// accept = base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
pub fn computeAcceptKey(ws_key: []const u8) [28]u8 {
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(ws_key);
    hasher.update(magic);
    const digest = hasher.finalResult();
    var result: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&result, &digest);
    return result;
}

/// Check whether the handshake response contains "101" status and the
/// correct Sec-WebSocket-Accept header.
pub fn validateHandshakeResponse(response: []const u8, expected_accept: []const u8) bool {
    // Check for HTTP 101 status
    if (std.mem.indexOf(u8, response, "101") == null) return false;

    // Find Sec-WebSocket-Accept header (case-insensitive search)
    const accept_header = "sec-websocket-accept: ";
    var lower_buf: [4096]u8 = undefined;
    const check_len = @min(response.len, lower_buf.len);
    for (response[0..check_len], 0..) |c, i| {
        lower_buf[i] = std.ascii.toLower(c);
    }
    const lower_response = lower_buf[0..check_len];

    if (std.mem.indexOf(u8, lower_response, accept_header)) |header_start| {
        const value_start = header_start + accept_header.len;
        // Find end of header value (terminated by \r\n)
        const value_end = blk: {
            const slice = response[value_start..];
            break :blk if (std.mem.indexOfScalar(u8, slice, '\r')) |idx| idx + value_start else null;
        } orelse response.len;
        const accept_value = response[value_start..value_end];

        // Trim whitespace
        const trimmed = std.mem.trim(u8, accept_value, " \t");
        return std.mem.eql(u8, trimmed, expected_accept);
    }

    return false;
}

// ---------------------------------------------------------------------------
// WsTransport
// ---------------------------------------------------------------------------

/// WebSocket transport for Ethereum JSON-RPC communication.
///
/// Supports both ws:// (plain TCP) and wss:// (TLS) connections.
/// For wss://, TLS state is heap-allocated to ensure stable pointers
/// for the TLS client's reader/writer interfaces.
///
/// Usage:
///   var transport = try WsTransport.connect(allocator, "ws://localhost:8545", io);
///   defer transport.close();
///   const response = try transport.request("eth_blockNumber", "[]");
///   defer allocator.free(response);
pub const WsTransport = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    next_id: u64,

    // Read buffer for incoming WebSocket frame data
    read_buf: [65536]u8 = undefined,
    read_pos: usize = 0,
    read_end: usize = 0,

    /// Total number of frames (data + control) received since this transport
    /// was opened. Higher-level wrappers can sample this to detect liveness
    /// of pong responses without piercing the abstraction.
    frames_received: u64 = 0,

    // Track whether we use TLS
    is_tls: bool = false,

    // Heap-allocated TLS state, only populated for wss:// connections.
    // Must be heap-allocated because the TLS client stores pointers to
    // the stream reader/writer interfaces, which must remain stable.
    tls_state: ?*TlsState = null,

    /// Opaque TLS state. Heap-allocated so that the stream reader/writer
    /// (whose interface pointers are captured by the TLS client) have
    /// stable addresses for the lifetime of the connection.
    pub const TlsState = struct {
        tls_client: std.crypto.tls.Client,
        stream_reader: std.Io.net.Stream.Reader,
        stream_writer: std.Io.net.Stream.Writer,

        // CA store used to verify the server certificate during the
        // handshake. The TLS client rescans the system store into this
        // bundle (guarded by the lock) inside `init`.
        ca_lock: std.Io.RwLock,
        ca_bundle: std.crypto.Certificate.Bundle,

        // Buffers that the TLS client and stream reader/writer reference.
        // These are stored here so they live as long as the TLS client.
        // The socket-side read buffer must hold at least one full TLS
        // ciphertext record (`min_buffer_len`); the others are sized the
        // same for headroom.
        tls_read_buf: [std.crypto.tls.Client.min_buffer_len]u8,
        socket_write_buf: [std.crypto.tls.Client.min_buffer_len]u8,
        socket_read_buf: [std.crypto.tls.Client.min_buffer_len]u8,
        stream_write_buf: [std.crypto.tls.Client.min_buffer_len]u8,
    };

    pub const TransportError = error{
        ConnectionFailed,
        HandshakeFailed,
        InvalidFrame,
        ConnectionClosed,
        PayloadTooLarge,
        OutOfMemory,
        TlsInitFailed,
        WriteError,
        ReadError,
        Timeout,
    };

    /// Connect to a WebSocket endpoint.
    ///
    /// Parses the URL, opens a TCP connection, optionally wraps it in TLS,
    /// and performs the WebSocket upgrade handshake.
    pub fn connect(allocator: std.mem.Allocator, url: []const u8, io: std.Io) TransportError!WsTransport {
        const parsed = parseUrl(url) catch return error.ConnectionFailed;

        // Open TCP connection. Try the host as an IP literal first, then
        // fall back to DNS resolution.
        const stream = blk: {
            if (std.Io.net.IpAddress.parse(parsed.host, parsed.port)) |addr| {
                break :blk addr.connect(io, .{ .mode = .stream }) catch
                    return error.ConnectionFailed;
            } else |_| {
                const host_name = std.Io.net.HostName.init(parsed.host) catch
                    return error.ConnectionFailed;
                break :blk host_name.connect(io, parsed.port, .{ .mode = .stream }) catch
                    return error.ConnectionFailed;
            }
        };
        errdefer stream.close(io);

        var transport = WsTransport{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .next_id = 1,
            .is_tls = parsed.is_tls,
        };

        if (parsed.is_tls) {
            transport.tls_state = initTls(allocator, io, stream, parsed.host) catch
                return error.TlsInitFailed;
        }

        // WebSocket handshake
        transport.performHandshake(parsed.host, parsed.port, parsed.path) catch
            return error.HandshakeFailed;

        return transport;
    }

    /// Initialize TLS state on the heap.
    fn initTls(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, host: []const u8) !*TlsState {
        const state = try allocator.create(TlsState);
        errdefer allocator.destroy(state);

        // Initialize the stream reader/writer with buffers stored in the state.
        state.stream_reader = stream.reader(io, &state.socket_read_buf);
        state.stream_writer = stream.writer(io, &state.stream_write_buf);

        // System CA certificates for verification. The TLS client rescans
        // the system store into `ca_bundle` during init; the bundle is only
        // needed for the handshake, so it is freed once init completes.
        state.ca_lock = .init;
        state.ca_bundle = .empty;
        defer {
            state.ca_bundle.deinit(allocator);
            state.ca_bundle = .empty;
        }

        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);

        state.tls_client = std.crypto.tls.Client.init(
            &state.stream_reader.interface,
            &state.stream_writer.interface,
            .{
                .host = .{ .explicit = host },
                .ca = .{ .bundle = .{
                    .gpa = allocator,
                    .io = io,
                    .lock = &state.ca_lock,
                    .bundle = &state.ca_bundle,
                } },
                .read_buffer = &state.tls_read_buf,
                .write_buffer = &state.socket_write_buf,
                .entropy = &entropy,
                .realtime_now = std.Io.Clock.now(.real, io),
            },
        ) catch return error.TlsInitFailed;

        return state;
    }

    /// Close the WebSocket connection and free resources.
    pub fn close(self: *WsTransport) void {
        // Try to send a close frame (best effort)
        self.sendFrame(&.{}, .close) catch {};
        self.stream.close(self.io);

        // Free heap-allocated TLS state
        if (self.tls_state) |state| {
            self.allocator.destroy(state);
            self.tls_state = null;
        }
    }

    /// Send a JSON-RPC request and wait for the matching response.
    /// Returns the raw JSON response. Caller owns the returned memory.
    pub fn request(self: *WsTransport, method: []const u8, params_json: []const u8) ![]u8 {
        const id = self.next_id;
        self.next_id += 1;

        // Build JSON-RPC request
        const req = std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s},\"id\":{d}}}",
            .{ method, params_json, id },
        ) catch return error.OutOfMemory;
        defer self.allocator.free(req);

        // Send as text frame
        try self.sendFrame(req, .text);

        // Read frames until we get a response matching our request ID
        while (true) {
            const frame_data = try self.readFrame();
            errdefer self.allocator.free(frame_data);

            // Check if this response matches our request ID.
            // We look for "id":N pattern in the JSON response.
            var id_buf: [32]u8 = undefined;
            const id_str = std.fmt.bufPrint(&id_buf, "\"id\":{d}", .{id}) catch unreachable;

            if (std.mem.indexOf(u8, frame_data, id_str) != null) {
                return frame_data;
            }

            // Not our response (could be a subscription notification or
            // a response for a different ID); discard and keep reading.
            self.allocator.free(frame_data);
        }
    }

    /// Send a raw WebSocket text frame.
    pub fn sendText(self: *WsTransport, payload: []const u8) !void {
        return self.sendFrame(payload, .text);
    }

    /// Send a WebSocket ping frame with the given payload (RFC 6455 limits
    /// payload to 125 bytes; the caller is responsible for honoring that).
    /// The peer is expected to reply with a pong carrying the same payload.
    pub fn sendPing(self: *WsTransport, payload: []const u8) !void {
        return self.sendFrame(payload, .ping);
    }

    /// Read the next WebSocket message (text or binary).
    /// Caller owns the returned memory.
    pub fn readMessage(self: *WsTransport) ![]u8 {
        return self.readFrame();
    }

    /// Read the next WebSocket message with a deadline.
    ///
    /// `deadline_ms` is an absolute timestamp from `eth.runtime.milliTimestamp()`.
    /// Returns the payload (caller owns memory) on success, or null if the
    /// deadline expires before a complete data frame is available.
    ///
    /// Control frames (ping/pong) are handled transparently as in `readFrame`.
    /// Note: with TLS, a partially-arrived TLS record may cause the underlying
    /// read to block briefly past the deadline while the record is assembled.
    pub fn readMessageDeadline(self: *WsTransport, deadline_ms: i64) !?[]u8 {
        return self.readFrameDeadline(deadline_ms);
    }

    /// Wait for the underlying socket to become readable, or for `timeout_ms`
    /// to elapse. Returns true if data is ready, false on timeout.
    /// Pass a negative timeout to block indefinitely.
    pub fn pollReadable(self: *WsTransport, timeout_ms: i32) !bool {
        // If the read buffer already has unconsumed bytes, we are immediately
        // readable from the caller's perspective.
        if (self.read_end > self.read_pos) return true;
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const n = std.posix.poll(&fds, timeout_ms) catch return error.ReadError;
        if (n == 0) return false;
        // POLLERR / POLLHUP / POLLNVAL all indicate the socket is no longer
        // usable; surface that as ReadError so the caller triggers reconnect.
        if (fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) {
            return error.ReadError;
        }
        return (fds[0].revents & std.posix.POLL.IN) != 0;
    }

    // -- Internal methods --

    /// Send a WebSocket frame with the given opcode and payload.
    fn sendFrame(self: *WsTransport, payload: []const u8, opcode: Opcode) !void {
        // Generate random mask key (required for client-to-server frames)
        var mask_key: [4]u8 = undefined;
        self.io.random(&mask_key);

        const frame = encodeFrame(self.allocator, opcode, payload, mask_key) catch
            return error.OutOfMemory;
        defer self.allocator.free(frame);

        self.writeAll(frame) catch return error.WriteError;
    }

    /// Read a complete WebSocket frame. Returns the unmasked payload.
    /// Caller owns the returned memory.
    /// Handles ping frames internally by responding with pong.
    fn readFrame(self: *WsTransport) ![]u8 {
        return (try self.readFrameImpl(null)) orelse unreachable;
    }

    /// Read a complete WebSocket frame, returning null on deadline.
    /// `deadline_ms` is absolute (`eth.runtime.milliTimestamp()` units).
    fn readFrameDeadline(self: *WsTransport, deadline_ms: i64) !?[]u8 {
        return self.readFrameImpl(deadline_ms);
    }

    /// Shared implementation for `readFrame` (no deadline) and
    /// `readFrameDeadline` (returns null on timeout).
    fn readFrameImpl(self: *WsTransport, deadline_ms: ?i64) !?[]u8 {
        while (true) {
            // Ensure we have at least 2 bytes for the header
            if (!try self.ensureReadBufDeadline(2, deadline_ms)) return null;

            const available = self.read_buf[self.read_pos..self.read_end];
            const header_opt = decodeFrameHeader(available);

            if (header_opt == null) {
                // Need more data for header
                if (!try self.fillReadBufDeadline(deadline_ms)) return null;
                continue;
            }

            const header = header_opt.?;
            const total_frame_size = header.header_size + @as(usize, @intCast(header.payload_len));

            if (header.payload_len > 16 * 1024 * 1024) {
                return error.PayloadTooLarge;
            }

            // Ensure we have the entire frame in the buffer
            if (!try self.ensureReadBufDeadline(total_frame_size, deadline_ms)) return null;

            const payload_start = self.read_pos + header.header_size;
            const payload_end = payload_start + @as(usize, @intCast(header.payload_len));

            // Copy payload out to heap
            const payload_len: usize = @intCast(header.payload_len);
            const payload = self.allocator.alloc(u8, payload_len) catch
                return error.OutOfMemory;
            errdefer self.allocator.free(payload);
            @memcpy(payload, self.read_buf[payload_start..payload_end]);

            // Unmask if needed (server-to-client frames are typically unmasked,
            // but handle masked frames for correctness)
            if (header.masked) {
                unmaskPayload(payload, header.mask_key);
            }

            // Advance read position past this frame
            self.read_pos = payload_end;
            self.frames_received +%= 1;

            // Handle control frames transparently
            switch (header.opcode) {
                .ping => {
                    // RFC 6455: respond to ping with pong carrying same payload
                    self.sendFrame(payload, .pong) catch {};
                    self.allocator.free(payload);
                    continue;
                },
                .close => {
                    self.allocator.free(payload);
                    return error.ConnectionClosed;
                },
                .pong => {
                    // Silently ignore unsolicited pong frames
                    self.allocator.free(payload);
                    continue;
                },
                .text, .binary, .continuation => {
                    return payload;
                },
                _ => {
                    self.allocator.free(payload);
                    return error.InvalidFrame;
                },
            }
        }
    }

    /// Perform the WebSocket upgrade handshake over the connection.
    fn performHandshake(self: *WsTransport, host: []const u8, port: u16, path: []const u8) !void {
        // Generate random key
        var random_bytes: [16]u8 = undefined;
        self.io.random(&random_bytes);
        const ws_key = generateWebSocketKey(random_bytes);

        // Build and send handshake request
        const req = buildHandshakeRequest(self.allocator, host, port, path, &ws_key) catch
            return error.HandshakeFailed;
        defer self.allocator.free(req);

        self.writeAll(req) catch return error.HandshakeFailed;

        // Read response (up to 4KB should be enough for HTTP headers)
        var response_buf: [4096]u8 = undefined;
        var total_read: usize = 0;
        while (total_read < response_buf.len) {
            const n = self.readSome(response_buf[total_read..]) catch return error.HandshakeFailed;
            if (n == 0) return error.HandshakeFailed;
            total_read += n;

            // Check if we have the full response (ends with \r\n\r\n)
            if (total_read >= 4) {
                if (std.mem.indexOf(u8, response_buf[0..total_read], "\r\n\r\n") != null) {
                    break;
                }
            }
        }

        const expected_accept = computeAcceptKey(&ws_key);
        if (!validateHandshakeResponse(response_buf[0..total_read], &expected_accept)) {
            return error.HandshakeFailed;
        }
    }

    /// Ensure the read buffer has at least `min_bytes` available from
    /// the current read_pos.
    fn ensureReadBuf(self: *WsTransport, min_bytes: usize) !void {
        _ = try self.ensureReadBufDeadline(min_bytes, null);
    }

    /// Read more data from the network into the read buffer.
    fn fillReadBuf(self: *WsTransport) !void {
        _ = try self.fillReadBufDeadline(null);
    }

    /// Ensure the read buffer has at least `min_bytes` available, respecting
    /// `deadline_ms` (absolute milliseconds). Returns true on success, false
    /// if the deadline expired before enough bytes arrived.
    fn ensureReadBufDeadline(self: *WsTransport, min_bytes: usize, deadline_ms: ?i64) !bool {
        while (self.read_end - self.read_pos < min_bytes) {
            if (!try self.fillReadBufDeadline(deadline_ms)) return false;
        }
        return true;
    }

    /// Read more data from the network into the read buffer, optionally
    /// bounded by `deadline_ms`. Returns true on read, false on timeout.
    fn fillReadBufDeadline(self: *WsTransport, deadline_ms: ?i64) !bool {
        // Compact: shift remaining data to the front
        if (self.read_pos > 0) {
            const remaining = self.read_end - self.read_pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[self.read_pos..self.read_end]);
            }
            self.read_end = remaining;
            self.read_pos = 0;
        }

        if (deadline_ms) |dl| {
            const now = runtime.milliTimestamp(self.io);
            if (now >= dl) return false;
            const wait_i64 = dl - now;
            const wait_ms: i32 = if (wait_i64 > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(wait_i64);
            const ready = try self.pollReadable(wait_ms);
            if (!ready) return false;
        }

        const n = self.readSome(self.read_buf[self.read_end..]) catch return error.ReadError;
        if (n == 0) return error.ConnectionClosed;
        self.read_end += n;
        return true;
    }

    /// Write all bytes to the underlying transport (plain TCP or TLS).
    fn writeAll(self: *WsTransport, data: []const u8) !void {
        if (self.tls_state) |tls| {
            // Write through TLS: use the TLS client's writer
            tls.tls_client.writer.writeAll(data) catch return error.WriteError;
            tls.tls_client.writer.flush() catch return error.WriteError;
        } else {
            // Plain TCP: write through an unbuffered transient stream writer.
            var stream_writer = self.stream.writer(self.io, &.{});
            stream_writer.interface.writeAll(data) catch return error.WriteError;
            stream_writer.interface.flush() catch return error.WriteError;
        }
    }

    /// Read some bytes from the underlying transport (plain TCP or TLS).
    ///
    /// Performs a single underlying read and returns however many bytes are
    /// available (like a raw `recv`), rather than blocking until `buf` is
    /// full. Returns 0 on end of stream.
    fn readSome(self: *WsTransport, buf: []u8) !usize {
        var data: [1][]u8 = .{buf};
        if (self.tls_state) |tls| {
            // Read through TLS: use the TLS client's reader. A successful
            // read of 0 bytes just means a record with no application data
            // was processed, so try again.
            while (true) {
                const n = tls.tls_client.reader.readVec(&data) catch |err| switch (err) {
                    error.EndOfStream => return 0,
                    else => return error.ReadError,
                };
                if (n != 0) return n;
            }
        } else {
            // Plain TCP: read through an unbuffered transient stream reader.
            var stream_reader = self.stream.reader(self.io, &.{});
            return stream_reader.interface.readVec(&data) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => error.ReadError,
            };
        }
    }
};

// ---------------------------------------------------------------------------
// Reconnect loop
// ---------------------------------------------------------------------------

/// Options for `connectWithReconnect`.
pub const ReconnectOpts = struct {
    /// Initial backoff in milliseconds. Default: 1_000.
    initial_backoff_ms: u64 = 1_000,
    /// Maximum backoff cap in milliseconds. Default: 30_000.
    max_backoff_ms: u64 = 30_000,
    /// Optional callback invoked before each reconnect attempt.
    /// Receives the backoff delay that will be applied.
    on_reconnect: ?*const fn (backoff_ms: u64) void = null,
};

/// Connect to a WebSocket endpoint and stream messages forever, reconnecting
/// with exponential backoff on disconnection or error.
///
/// On each successful connection `callback` is invoked with a pointer to the
/// live `WsTransport`. The callback should perform any subscription setup
/// (e.g. `eth_subscribe`) and then read messages in a loop until the
/// connection drops. When the callback returns -- whether cleanly or with an
/// error -- the transport is closed and a reconnect is scheduled.
///
/// This function never returns under normal operation.
pub fn connectWithReconnect(
    allocator: std.mem.Allocator,
    url: []const u8,
    io: std.Io,
    opts: ReconnectOpts,
    callback: *const fn (transport: *WsTransport) anyerror!void,
) void {
    var backoff_ms = opts.initial_backoff_ms;

    while (true) {
        if (WsTransport.connect(allocator, url, io)) |transport_val| {
            var transport = transport_val;
            defer transport.close();
            if (callback(&transport)) |_| {
                // Clean close -- reset backoff.
                backoff_ms = opts.initial_backoff_ms;
            } else |_| {}
        } else |_| {}

        if (opts.on_reconnect) |cb| cb(backoff_ms);
        runtime.sleepMs(io, backoff_ms);

        // Guard against overflow before clamping.
        backoff_ms = if (backoff_ms > opts.max_backoff_ms / 2)
            opts.max_backoff_ms
        else
            backoff_ms * 2;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "parseUrl - ws basic" {
    const result = try parseUrl("ws://localhost:8545/ws");
    try std.testing.expectEqualStrings("localhost", result.host);
    try std.testing.expectEqual(@as(u16, 8545), result.port);
    try std.testing.expectEqualStrings("/ws", result.path);
    try std.testing.expect(!result.is_tls);
}

test "parseUrl - wss with default port" {
    const result = try parseUrl("wss://mainnet.infura.io/ws/v3/abc123");
    try std.testing.expectEqualStrings("mainnet.infura.io", result.host);
    try std.testing.expectEqual(@as(u16, 443), result.port);
    try std.testing.expectEqualStrings("/ws/v3/abc123", result.path);
    try std.testing.expect(result.is_tls);
}

test "parseUrl - ws default port" {
    const result = try parseUrl("ws://localhost");
    try std.testing.expectEqualStrings("localhost", result.host);
    try std.testing.expectEqual(@as(u16, 80), result.port);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expect(!result.is_tls);
}

test "parseUrl - invalid scheme" {
    try std.testing.expectError(error.InvalidScheme, parseUrl("http://localhost"));
}

test "parseUrl - missing host" {
    try std.testing.expectError(error.MissingHost, parseUrl("ws://"));
}

test "parseUrl - wss explicit port" {
    const result = try parseUrl("wss://node.example.com:9546/");
    try std.testing.expectEqualStrings("node.example.com", result.host);
    try std.testing.expectEqual(@as(u16, 9546), result.port);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expect(result.is_tls);
}

test "parseUrl - ws with just path slash" {
    const result = try parseUrl("ws://127.0.0.1:8546/");
    try std.testing.expectEqualStrings("127.0.0.1", result.host);
    try std.testing.expectEqual(@as(u16, 8546), result.port);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expect(!result.is_tls);
}

test "parseUrl - deep path" {
    const result = try parseUrl("wss://eth-mainnet.g.alchemy.com/v2/my-api-key");
    try std.testing.expectEqualStrings("eth-mainnet.g.alchemy.com", result.host);
    try std.testing.expectEqual(@as(u16, 443), result.port);
    try std.testing.expectEqualStrings("/v2/my-api-key", result.path);
    try std.testing.expect(result.is_tls);
}

test "encodeFrame - small text frame" {
    const allocator = std.testing.allocator;
    const payload = "Hello";
    const mask_key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };

    const frame = try encodeFrame(allocator, .text, payload, mask_key);
    defer allocator.free(frame);

    // Byte 0: FIN(0x80) | text(0x01) = 0x81
    try std.testing.expectEqual(@as(u8, 0x81), frame[0]);

    // Byte 1: MASK(0x80) | len(5) = 0x85
    try std.testing.expectEqual(@as(u8, 0x85), frame[1]);

    // Bytes 2-5: mask key
    try std.testing.expectEqual(@as(u8, 0x37), frame[2]);
    try std.testing.expectEqual(@as(u8, 0xfa), frame[3]);
    try std.testing.expectEqual(@as(u8, 0x21), frame[4]);
    try std.testing.expectEqual(@as(u8, 0x3d), frame[5]);

    // Bytes 6+: masked payload
    try std.testing.expectEqual(@as(u8, 'H' ^ 0x37), frame[6]);
    try std.testing.expectEqual(@as(u8, 'e' ^ 0xfa), frame[7]);
    try std.testing.expectEqual(@as(u8, 'l' ^ 0x21), frame[8]);
    try std.testing.expectEqual(@as(u8, 'l' ^ 0x3d), frame[9]);
    try std.testing.expectEqual(@as(u8, 'o' ^ 0x37), frame[10]);

    // Total frame size: 2 + 4 + 5 = 11
    try std.testing.expectEqual(@as(usize, 11), frame.len);
}

test "encodeFrame - empty payload" {
    const allocator = std.testing.allocator;
    const mask_key = [4]u8{ 0x11, 0x22, 0x33, 0x44 };

    const frame = try encodeFrame(allocator, .text, &.{}, mask_key);
    defer allocator.free(frame);

    try std.testing.expectEqual(@as(u8, 0x81), frame[0]); // FIN | text
    try std.testing.expectEqual(@as(u8, 0x80), frame[1]); // MASK | 0
    try std.testing.expectEqual(@as(usize, 6), frame.len); // 2 + 4 mask bytes
}

test "encodeFrame - medium payload (126 bytes)" {
    const allocator = std.testing.allocator;
    const payload = @as([200]u8, @splat('A'));
    const mask_key = [4]u8{ 0x01, 0x02, 0x03, 0x04 };

    const frame = try encodeFrame(allocator, .text, &payload, mask_key);
    defer allocator.free(frame);

    // Byte 0: FIN | text
    try std.testing.expectEqual(@as(u8, 0x81), frame[0]);

    // Byte 1: MASK | 126 (extended length indicator)
    try std.testing.expectEqual(@as(u8, 0x80 | 126), frame[1]);

    // Bytes 2-3: 16-bit length = 200
    try std.testing.expectEqual(@as(u8, 0), frame[2]);
    try std.testing.expectEqual(@as(u8, 200), frame[3]);

    // Bytes 4-7: mask key
    try std.testing.expectEqual(@as(u8, 0x01), frame[4]);

    // Total: 2 + 2 + 4 + 200 = 208
    try std.testing.expectEqual(@as(usize, 208), frame.len);
}

test "encodeFrame - close frame" {
    const allocator = std.testing.allocator;
    const mask_key = [4]u8{ 0, 0, 0, 0 };

    const frame = try encodeFrame(allocator, .close, &.{}, mask_key);
    defer allocator.free(frame);

    // Byte 0: FIN | close(0x08) = 0x88
    try std.testing.expectEqual(@as(u8, 0x88), frame[0]);

    // Byte 1: MASK | 0 length = 0x80
    try std.testing.expectEqual(@as(u8, 0x80), frame[1]);

    // Total: 2 + 4 = 6 (header + mask key, no payload)
    try std.testing.expectEqual(@as(usize, 6), frame.len);
}

test "encodeFrame - ping frame with payload" {
    const allocator = std.testing.allocator;
    const mask_key = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const payload = "ping";

    const frame = try encodeFrame(allocator, .ping, payload, mask_key);
    defer allocator.free(frame);

    // Byte 0: FIN | ping(0x09) = 0x89
    try std.testing.expectEqual(@as(u8, 0x89), frame[0]);
    try std.testing.expectEqual(@as(u8, 0x84), frame[1]); // MASK | 4
}

test "encodeFrame - pong frame" {
    const allocator = std.testing.allocator;
    const mask_key = [4]u8{ 0x00, 0x00, 0x00, 0x00 };
    const payload = "pong";

    const frame = try encodeFrame(allocator, .pong, payload, mask_key);
    defer allocator.free(frame);

    // Byte 0: FIN | pong(0x0A) = 0x8A
    try std.testing.expectEqual(@as(u8, 0x8A), frame[0]);
    try std.testing.expectEqual(@as(u8, 0x84), frame[1]); // MASK | 4

    // With zero mask, payload should be unchanged
    try std.testing.expectEqualStrings("pong", frame[6..10]);
}

test "decodeFrameHeader - small unmasked text" {
    const data = [_]u8{ 0x81, 0x05 }; // FIN | text, len=5
    const header = decodeFrameHeader(&data).?;

    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.text, header.opcode);
    try std.testing.expect(!header.masked);
    try std.testing.expectEqual(@as(u64, 5), header.payload_len);
    try std.testing.expectEqual(@as(usize, 2), header.header_size);
}

test "decodeFrameHeader - masked text" {
    const data = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d };
    const header = decodeFrameHeader(&data).?;

    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.text, header.opcode);
    try std.testing.expect(header.masked);
    try std.testing.expectEqual(@as(u64, 5), header.payload_len);
    try std.testing.expectEqual(@as(usize, 6), header.header_size);
    try std.testing.expectEqual(@as(u8, 0x37), header.mask_key[0]);
    try std.testing.expectEqual(@as(u8, 0xfa), header.mask_key[1]);
}

test "decodeFrameHeader - 16-bit extended length" {
    const data = [_]u8{ 0x81, 126, 0x01, 0x00 }; // len=256
    const header = decodeFrameHeader(&data).?;

    try std.testing.expectEqual(@as(u64, 256), header.payload_len);
    try std.testing.expectEqual(@as(usize, 4), header.header_size);
}

test "decodeFrameHeader - 64-bit extended length" {
    var data: [10]u8 = undefined;
    data[0] = 0x82; // FIN | binary
    data[1] = 127; // 64-bit length
    // Length = 70000 = 0x00_00_00_00_00_01_11_70
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0x01;
    data[8] = 0x11;
    data[9] = 0x70;

    const header = decodeFrameHeader(&data).?;
    try std.testing.expectEqual(@as(u64, 70000), header.payload_len);
    try std.testing.expectEqual(@as(usize, 10), header.header_size);
    try std.testing.expectEqual(Opcode.binary, header.opcode);
}

test "decodeFrameHeader - insufficient bytes returns null" {
    const data = [_]u8{0x81}; // Only 1 byte
    try std.testing.expect(decodeFrameHeader(&data) == null);
}

test "decodeFrameHeader - insufficient for 16-bit length" {
    const data = [_]u8{ 0x81, 126, 0x01 }; // Need 4 bytes, only have 3
    try std.testing.expect(decodeFrameHeader(&data) == null);
}

test "decodeFrameHeader - insufficient for 64-bit length" {
    const data = [_]u8{ 0x81, 127, 0x00, 0x00, 0x00 }; // Need 10, only 5
    try std.testing.expect(decodeFrameHeader(&data) == null);
}

test "decodeFrameHeader - insufficient for mask key" {
    const data = [_]u8{ 0x81, 0x85, 0x37, 0xfa }; // Need 6, only 4
    try std.testing.expect(decodeFrameHeader(&data) == null);
}

test "decodeFrameHeader - close frame" {
    const data = [_]u8{ 0x88, 0x00 }; // FIN | close, len=0
    const header = decodeFrameHeader(&data).?;

    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.close, header.opcode);
    try std.testing.expectEqual(@as(u64, 0), header.payload_len);
}

test "decodeFrameHeader - ping frame" {
    const data = [_]u8{ 0x89, 0x04 }; // FIN | ping, len=4
    const header = decodeFrameHeader(&data).?;

    try std.testing.expectEqual(Opcode.ping, header.opcode);
    try std.testing.expectEqual(@as(u64, 4), header.payload_len);
}

test "decodeFrameHeader - pong frame" {
    const data = [_]u8{ 0x8A, 0x00 }; // FIN | pong, len=0
    const header = decodeFrameHeader(&data).?;

    try std.testing.expectEqual(Opcode.pong, header.opcode);
}

test "decodeFrameHeader - non-fin frame" {
    const data = [_]u8{ 0x01, 0x03 }; // no FIN | text, len=3
    const header = decodeFrameHeader(&data).?;

    try std.testing.expect(!header.fin);
    try std.testing.expectEqual(Opcode.text, header.opcode);
    try std.testing.expectEqual(@as(u64, 3), header.payload_len);
}

test "decodeFrameHeader - zero length" {
    const data = [_]u8{ 0x81, 0x00 }; // FIN | text, len=0
    const header = decodeFrameHeader(&data).?;

    try std.testing.expectEqual(@as(u64, 0), header.payload_len);
    try std.testing.expectEqual(@as(usize, 2), header.header_size);
}

test "unmaskPayload - Hello" {
    var payload = [_]u8{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const mask_key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    unmaskPayload(&payload, mask_key);

    try std.testing.expectEqual(@as(u8, 'H'), payload[0]);
    try std.testing.expectEqual(@as(u8, 'e'), payload[1]);
    try std.testing.expectEqual(@as(u8, 'l'), payload[2]);
    try std.testing.expectEqual(@as(u8, 'l'), payload[3]);
    try std.testing.expectEqual(@as(u8, 'o'), payload[4]);
}

test "unmaskPayload - empty" {
    var payload = [_]u8{};
    unmaskPayload(&payload, .{ 0xFF, 0xFF, 0xFF, 0xFF });
}

test "unmaskPayload - roundtrip" {
    const original = "Hello, World!";
    var masked: [original.len]u8 = undefined;
    @memcpy(&masked, original);

    const mask_key = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    unmaskPayload(&masked, mask_key);

    // After masking, it should be different
    try std.testing.expect(!std.mem.eql(u8, &masked, original));

    // Unmasking again should restore original
    unmaskPayload(&masked, mask_key);
    try std.testing.expectEqualStrings(original, &masked);
}

test "unmaskPayload - zero mask is identity" {
    var payload = [_]u8{ 'a', 'b', 'c' };
    unmaskPayload(&payload, .{ 0, 0, 0, 0 });
    try std.testing.expectEqualStrings("abc", &payload);
}

test "generateWebSocketKey - produces 24 base64 chars" {
    const random = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const key = generateWebSocketKey(random);
    try std.testing.expectEqual(@as(usize, 24), key.len);

    // Verify it is valid base64 that decodes back to the original bytes
    var decoded: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&decoded, &key);
    try std.testing.expectEqualSlices(u8, &random, &decoded);
}

test "generateWebSocketKey - different inputs produce different keys" {
    const key1 = generateWebSocketKey(@as([16]u8, @splat(0)));
    const key2 = generateWebSocketKey(@as([16]u8, @splat(1)));
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "computeAcceptKey - RFC 6455 example" {
    // RFC 6455 Section 4.2.2 example:
    // Key: "dGhlIHNhbXBsZSBub25jZQ=="
    // Expected Accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(ws_key);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "computeAcceptKey - deterministic" {
    const key = "AQIDBAUGBwgJCgsMDQ4PEA==";
    const accept1 = computeAcceptKey(key);
    const accept2 = computeAcceptKey(key);
    try std.testing.expectEqualStrings(&accept1, &accept2);
}

test "buildHandshakeRequest - basic" {
    const allocator = std.testing.allocator;
    const req = try buildHandshakeRequest(allocator, "localhost", 8545, "/ws", "dGhlIHNhbXBsZSBub25jZQ==");
    defer allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "GET /ws HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: localhost:8545\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Upgrade: websocket\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Connection: Upgrade\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Version: 13\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\r\n\r\n") != null);
}

test "buildHandshakeRequest - standard port 80 omitted" {
    const allocator = std.testing.allocator;
    const req = try buildHandshakeRequest(allocator, "example.com", 80, "/", "abc=");
    defer allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, ":80") == null);
}

test "buildHandshakeRequest - standard port 443 omitted" {
    const allocator = std.testing.allocator;
    const req = try buildHandshakeRequest(allocator, "example.com", 443, "/", "abc=");
    defer allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "443") == null);
}

test "buildHandshakeRequest - deep path" {
    const allocator = std.testing.allocator;
    const req = try buildHandshakeRequest(allocator, "node.io", 9546, "/v2/my-key", "key=");
    defer allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "GET /v2/my-key HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: node.io:9546\r\n") != null);
}

test "validateHandshakeResponse - valid" {
    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const expected_accept = computeAcceptKey(ws_key);

    var response_buf: [256]u8 = undefined;
    const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{expected_accept}) catch unreachable;

    try std.testing.expect(validateHandshakeResponse(response, &expected_accept));
}

test "validateHandshakeResponse - wrong status" {
    const expected_accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    const response = "HTTP/1.1 400 Bad Request\r\n\r\n";
    try std.testing.expect(!validateHandshakeResponse(response, &expected_accept));
}

test "validateHandshakeResponse - wrong accept" {
    const expected_accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    const response = "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrongvalue\r\n\r\n";
    try std.testing.expect(!validateHandshakeResponse(response, &expected_accept));
}

test "validateHandshakeResponse - case insensitive header" {
    const ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const expected_accept = computeAcceptKey(ws_key);

    var response_buf: [256]u8 = undefined;
    const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\nsec-websocket-accept: {s}\r\n\r\n", .{expected_accept}) catch unreachable;

    try std.testing.expect(validateHandshakeResponse(response, &expected_accept));
}

test "encodeFrame then decodeFrameHeader roundtrip" {
    const allocator = std.testing.allocator;
    const payload = "test payload data";
    const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };

    const frame = try encodeFrame(allocator, .text, payload, mask_key);
    defer allocator.free(frame);

    const header = decodeFrameHeader(frame).?;
    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.text, header.opcode);
    try std.testing.expect(header.masked);
    try std.testing.expectEqual(@as(u64, payload.len), header.payload_len);

    // Extract and unmask
    const payload_start = header.header_size;
    const payload_end = payload_start + @as(usize, @intCast(header.payload_len));
    var extracted: [payload.len]u8 = undefined;
    @memcpy(&extracted, frame[payload_start..payload_end]);
    unmaskPayload(&extracted, header.mask_key);

    try std.testing.expectEqualStrings(payload, &extracted);
}

test "encodeFrame then decodeFrameHeader roundtrip - large payload" {
    const allocator = std.testing.allocator;
    const payload = @as([300]u8, @splat('X'));
    const mask_key = [4]u8{ 0xAB, 0xCD, 0xEF, 0x01 };

    const frame = try encodeFrame(allocator, .binary, &payload, mask_key);
    defer allocator.free(frame);

    const header = decodeFrameHeader(frame).?;
    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.binary, header.opcode);
    try std.testing.expect(header.masked);
    try std.testing.expectEqual(@as(u64, 300), header.payload_len);

    // Verify we can extract and unmask correctly
    const payload_start = header.header_size;
    const payload_end = payload_start + 300;
    var extracted: [300]u8 = undefined;
    @memcpy(&extracted, frame[payload_start..payload_end]);
    unmaskPayload(&extracted, header.mask_key);

    try std.testing.expectEqualSlices(u8, &payload, &extracted);
}

test "encodeFrame - exactly 125 bytes (max short length)" {
    const allocator = std.testing.allocator;
    const payload = @as([125]u8, @splat('Z'));
    const mask_key = [4]u8{ 1, 2, 3, 4 };

    const frame = try encodeFrame(allocator, .text, &payload, mask_key);
    defer allocator.free(frame);

    // Should use short length encoding (no extended length)
    try std.testing.expectEqual(@as(u8, 0x80 | 125), frame[1]);
    try std.testing.expectEqual(@as(usize, 2 + 4 + 125), frame.len);
}

test "encodeFrame - exactly 126 bytes (triggers extended 16-bit length)" {
    const allocator = std.testing.allocator;
    const payload = @as([126]u8, @splat('Z'));
    const mask_key = [4]u8{ 1, 2, 3, 4 };

    const frame = try encodeFrame(allocator, .text, &payload, mask_key);
    defer allocator.free(frame);

    // Should use 16-bit extended length
    try std.testing.expectEqual(@as(u8, 0x80 | 126), frame[1]);
    try std.testing.expectEqual(@as(u8, 0), frame[2]); // high byte
    try std.testing.expectEqual(@as(u8, 126), frame[3]); // low byte
    try std.testing.expectEqual(@as(usize, 2 + 2 + 4 + 126), frame.len);
}

test "Opcode values" {
    try std.testing.expectEqual(@as(u4, 0x1), @intFromEnum(Opcode.text));
    try std.testing.expectEqual(@as(u4, 0x2), @intFromEnum(Opcode.binary));
    try std.testing.expectEqual(@as(u4, 0x8), @intFromEnum(Opcode.close));
    try std.testing.expectEqual(@as(u4, 0x9), @intFromEnum(Opcode.ping));
    try std.testing.expectEqual(@as(u4, 0xA), @intFromEnum(Opcode.pong));
    try std.testing.expectEqual(@as(u4, 0x0), @intFromEnum(Opcode.continuation));
}

test "ReconnectOpts defaults" {
    const opts = ReconnectOpts{};
    try std.testing.expectEqual(@as(u64, 1_000), opts.initial_backoff_ms);
    try std.testing.expectEqual(@as(u64, 30_000), opts.max_backoff_ms);
    try std.testing.expect(opts.on_reconnect == null);
}

test "ReconnectOpts backoff clamping logic" {
    // Verify the overflow-safe backoff calculation used in connectWithReconnect.
    const max: u64 = 30_000;
    // Normal doubling
    var b: u64 = 1_000;
    b = if (b > max / 2) max else b * 2;
    try std.testing.expectEqual(@as(u64, 2_000), b);
    // Clamp when doubling would exceed max
    b = 20_000;
    b = if (b > max / 2) max else b * 2;
    try std.testing.expectEqual(@as(u64, 30_000), b);
    // Already at max
    b = 30_000;
    b = if (b > max / 2) max else b * 2;
    try std.testing.expectEqual(@as(u64, 30_000), b);
}
